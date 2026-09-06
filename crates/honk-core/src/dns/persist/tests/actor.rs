use std::sync::atomic::Ordering;

use tokio::sync::oneshot;

use crate::dns::cache::DnsCache;
use crate::dns::query::IngressProfile;

use super::*;

#[tokio::test]
async fn bounded_queue_drops_only_persistence_work_when_saturated() {
    let before = crate::stats::dns_snapshot();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir, "");
    let persister = DnsCachePersister::spawn(Arc::clone(&db));
    let mut cache = DnsCache::new(8);
    cache.set_persister(Some(persister.clone()));
    let service = cache.service();
    let guard = db.lock_for_test();
    let (key, response, _) = fixture(IngressProfile::Internal, None, upstream("default"));
    persister.save(key.clone(), response.clone().into(), unix_now() + 300);
    while !db.write_attempted_for_test() {
        std::thread::yield_now();
    }
    for _ in 0..(COMMAND_CAPACITY + 1024) {
        persister.save(key.clone(), response.clone().into(), unix_now() + 300);
    }
    service.put_exact(key.clone(), response, 300);
    assert_eq!(persister.counters().dropped_full, 1025);
    assert!(crate::stats::dns_snapshot().delta(before).persistence_drop >= 1);
    assert!(service.get_exact(&key).is_some());
    drop(guard);
    persister.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn new_epoch_put_queued_before_flush_command_survives_barrier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir, "");
    let persister = DnsCachePersister::spawn(Arc::clone(&db));
    let (old_key, response, _) = fixture(IngressProfile::Internal, None, upstream("old"));
    persister.save(old_key, response.clone().into(), unix_now() + 300);
    let epoch = persister
        .epoch
        .fetch_add(1, Ordering::SeqCst)
        .saturating_add(1);
    let (new_key, _, _) = fixture(IngressProfile::Internal, None, upstream("new"));
    persister.save(new_key.clone(), response.into(), unix_now() + 300);
    let (ack, receive) = oneshot::channel();
    persister.counters.queued.fetch_add(1, Ordering::Relaxed);
    persister
        .tx
        .send(Command::Flush { epoch, ack })
        .await
        .expect("flush command");
    receive.await.expect("flush ack").expect("flush succeeds");
    assert_eq!(db.load_dns_v2().expect("rows").len(), 1);
    persister.shutdown().await.expect("shutdown");

    let cache = DnsCache::new(8);
    let restart = DnsCachePersister::spawn(db);
    restart
        .restore(cache.service(), None)
        .await
        .expect("restore");
    assert!(cache.service().get_exact(&new_key).is_some());
    restart.shutdown().await.expect("restart shutdown");
}

#[tokio::test]
async fn flush_discards_late_old_epoch_and_preserves_new_epoch_put() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir, "");
    let persister = DnsCachePersister::spawn(Arc::clone(&db));
    let (old_key, response, _) = fixture(IngressProfile::Internal, None, upstream("old"));
    persister.flush().await.expect("flush");

    persister.counters.queued.fetch_add(1, Ordering::Relaxed);
    persister
        .tx
        .send(Command::Put(Put {
            epoch: 0,
            key: old_key,
            response: response.clone().into(),
            expire_at_unix: unix_now() + 300,
        }))
        .await
        .expect("late old put");
    let (new_key, _, _) = fixture(IngressProfile::Internal, None, upstream("new"));
    persister.save(new_key.clone(), response.into(), unix_now() + 300);
    persister.shutdown().await.expect("shutdown");

    assert_eq!(db.load_dns_v2().expect("rows").len(), 1);
    assert_eq!(persister.counters().old_epoch_discarded, 1);
    let cache = DnsCache::new(8);
    let restart = DnsCachePersister::spawn(db);
    assert_eq!(
        restart
            .restore(cache.service(), None)
            .await
            .expect("restore"),
        1
    );
    assert!(cache.service().get_exact(&new_key).is_some());
    restart.shutdown().await.expect("restart shutdown");
}

#[tokio::test]
async fn database_write_error_is_nonfatal_and_counted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir, "");
    db.set_query_only_for_test(true);
    let persister = DnsCachePersister::spawn(Arc::clone(&db));
    let (key, response, _) = fixture(IngressProfile::Internal, None, upstream("default"));
    persister.save(key, response.into(), unix_now() + 300);
    let error = persister.shutdown().await.expect_err("final write fails");
    assert!(matches!(error, PersistControlError::Database(_)));
    assert!(persister.counters().db_errors >= 1);
    db.set_query_only_for_test(false);
}

#[tokio::test]
async fn flush_reports_database_clear_failure() {
    let before = crate::stats::dns_snapshot();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir, "");
    db.save_dns_answer("legacy.example", 1, "answer", unix_now() + 300);
    db.set_query_only_for_test(true);
    let persister = DnsCachePersister::spawn(Arc::clone(&db));

    let error = persister
        .flush()
        .await
        .expect_err("flush must report DB error");

    assert!(matches!(error, PersistControlError::Database(_)));
    assert_eq!(persister.counters().db_errors, 1);
    assert!(
        crate::stats::dns_snapshot()
            .delta(before)
            .persistence_flush_failure
            >= 1
    );
    db.set_query_only_for_test(false);
    persister.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn out_of_order_flush_epochs_never_regress_or_strand_new_put() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir, "");
    let persister = DnsCachePersister::spawn(Arc::clone(&db));
    persister.epoch.store(2, Ordering::SeqCst);
    let (strong_ack, strong_receive) = oneshot::channel();
    persister.counters.queued.fetch_add(1, Ordering::Relaxed);
    persister
        .tx
        .send(Command::Flush {
            epoch: 2,
            ack: strong_ack,
        })
        .await
        .expect("strong flush");
    strong_receive
        .await
        .expect("strong ack")
        .expect("strong flush succeeds");
    let (key, response, _) = fixture(IngressProfile::Internal, None, upstream("epoch-2"));
    persister.save(key.clone(), response.into(), unix_now() + 300);
    let (stale_ack, stale_receive) = oneshot::channel();
    persister.counters.queued.fetch_add(1, Ordering::Relaxed);
    persister
        .tx
        .send(Command::Flush {
            epoch: 1,
            ack: stale_ack,
        })
        .await
        .expect("stale flush");

    stale_receive
        .await
        .expect("stale ack")
        .expect("stronger barrier subsumes stale flush");
    persister.shutdown().await.expect("shutdown");
    let restart = DnsCachePersister::spawn(db);
    let cache = DnsCache::new(8);
    assert_eq!(
        restart
            .restore(cache.service(), None)
            .await
            .expect("restore"),
        1
    );
    assert!(cache.service().get_exact(&key).is_some());
    restart.shutdown().await.expect("restart shutdown");
}

#[tokio::test]
async fn same_key_newer_epoch_survives_delayed_older_put_before_flush() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir, "");
    let persister = DnsCachePersister::spawn(Arc::clone(&db));
    let (key, newer_response, _) = fixture(IngressProfile::Internal, None, upstream("same-key"));
    let mut older_response = newer_response.clone();
    *older_response.last_mut().expect("response byte") = 99;
    persister.epoch.store(2, Ordering::SeqCst);
    persister.save(key.clone(), newer_response.clone().into(), unix_now() + 300);
    persister.epoch.store(1, Ordering::SeqCst);
    persister.save(key.clone(), older_response.into(), unix_now() + 300);
    persister.flush().await.expect("epoch-2 flush");
    assert_eq!(persister.counters().old_epoch_discarded, 1);
    persister.shutdown().await.expect("shutdown");
    let cache = DnsCache::new(8);
    let service = cache.service();
    let restart = DnsCachePersister::spawn(db);
    let count = restart
        .restore(Arc::clone(&service), None)
        .await
        .expect("restore");
    assert_eq!(count, 1);
    let entry = service.get_exact(&key).expect("restored response");
    assert_eq!(entry.response, newer_response);
    restart.shutdown().await.expect("restart shutdown");
}

#[tokio::test]
async fn failing_database_keeps_pending_bounded_and_timer_progressing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir, "");
    db.set_query_only_for_test(true);
    let persister = DnsCachePersister::spawn(Arc::clone(&db));
    for index in 0..(COMMAND_CAPACITY * 2) {
        let tag = format!("pending-{index}");
        let (key, response, _) = fixture(IngressProfile::Internal, None, upstream(&tag));
        persister.counters.queued.fetch_add(1, Ordering::Relaxed);
        persister
            .tx
            .send(Command::Put(Put {
                epoch: 0,
                key,
                response: response.into(),
                expire_at_unix: unix_now() + 300,
            }))
            .await
            .expect("bounded send");
    }
    let cache = DnsCache::new(8);
    persister
        .restore(cache.service(), None)
        .await
        .expect("ordering barrier");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while persister.counters().write_attempts == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("periodic write attempt");

    let counters = persister.counters();
    assert_eq!(counters.pending, COMMAND_CAPACITY);
    assert_eq!(counters.dropped_pending_full, COMMAND_CAPACITY as u64);
    assert!(counters.write_attempts > 0);
    assert!(persister.shutdown().await.is_err());
    db.set_query_only_for_test(false);
}

#[tokio::test]
async fn shutdown_performs_final_write_without_periodic_wait() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir, "");
    let persister = DnsCachePersister::spawn(Arc::clone(&db));
    let (key, response, _) = fixture(IngressProfile::Internal, None, upstream("default"));
    persister.save(key, response.into(), unix_now() + 300);
    persister.shutdown().await.expect("shutdown");
    assert_eq!(db.load_dns_v2().expect("rows").len(), 1);
}
#[tokio::test]
async fn exact_removal_dominates_queued_upsert_and_durable_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = test_db(&dir, "");
    let (key, response, _) = fixture(IngressProfile::Internal, None, upstream("default"));

    let initial = DnsCachePersister::spawn(Arc::clone(&db));
    initial.save(key.clone(), response.clone().into(), unix_now() + 300);
    initial.shutdown().await.expect("initial shutdown");
    assert_eq!(db.load_dns_v2().expect("durable row").len(), 1);

    let persister = DnsCachePersister::spawn(Arc::clone(&db));
    persister.save(key.clone(), response.into(), unix_now() + 300);
    persister.remove(key);
    persister.shutdown().await.expect("removal shutdown");
    assert!(db.load_dns_v2().expect("rows").is_empty());
    let restored = DnsCache::new(8);
    let restart = DnsCachePersister::spawn(db);
    assert_eq!(
        restart
            .restore(restored.service(), None)
            .await
            .expect("restore"),
        0
    );
    restart.shutdown().await.expect("restart shutdown");
}
