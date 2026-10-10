use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::dns::cache::{CacheInvalidation, DnsCache};

use super::*;

#[tokio::test]
async fn targeted_deletion_orders_queued_puts_preserves_unrelated_rows_and_rejects_late_work() {
    let dir = tempfile::tempdir().unwrap();
    let db = test_db(&dir);
    db.save_clash_global("node-a");
    let persister = DnsCachePersister::spawn(db.clone());
    let mut cache = DnsCache::new(64);
    cache.set_persister(Some(persister.clone()));
    let service = cache.service();
    let (first, response, _) = fixture(IngressProfile::Internal, None, upstream("first"));
    let (second, _, _) = fixture(IngressProfile::Tcp, None, upstream("second"));
    service.put_exact(first.clone(), response.clone(), 300, None);
    service.put_exact(second.clone(), response.clone(), 300, None);
    let first_id = service.entry_id(&first).unwrap();
    let result = service
        .invalidate(CacheInvalidation::Id(first_id))
        .await
        .unwrap();
    assert_eq!((result.deleted, result.persistent), (1, true));
    assert!(service.entry_id(&first).is_none());
    assert!(service.entry_id(&second).is_some());
    persister.counters.queued.fetch_add(1, Ordering::Relaxed);
    persister
        .tx
        .send(Command::Put(Put {
            epoch: 0,
            key: first.clone(),
            response: response.clone().into(),
            expire_at_unix: unix_now() + 300,
        }))
        .await
        .unwrap();
    persister.shutdown().await.unwrap();
    let rows = db.load_dns().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, codec::key_suffix(&second));
    let restarted = DnsCachePersister::spawn(db.clone());
    cache.set_persister(Some(restarted.clone()));
    // Evicted runtime entries still have to be deleted by name from durable storage.
    service.clear();
    let result = service
        .invalidate(CacheInvalidation::Name {
            name: "EXAMPLE.COM.".into(),
            types: vec![1],
        })
        .await
        .unwrap();
    assert_eq!(result.deleted, 0);
    assert!(db.load_dns().unwrap().is_empty());
    assert_eq!(db.load_clash_global().as_deref(), Some("node-a"));
    restarted.shutdown().await.unwrap();
}

#[tokio::test]
async fn overlapping_mutations_and_cancelled_waiters_keep_publication_and_actor_ordered() {
    let dir = tempfile::tempdir().unwrap();
    let db = test_db(&dir);
    let persister = DnsCachePersister::spawn(db.clone());
    let mut cache = DnsCache::new(64);
    cache.set_persister(Some(persister.clone()));
    let service = cache.service();
    let (first, response, _) = fixture(IngressProfile::Internal, None, upstream("first"));
    let (second, _, _) = fixture(IngressProfile::Internal, None, upstream("second"));
    let old_epoch = service.publication_epoch();
    service.put_exact(first.clone(), response.clone(), 300, None);
    service.put_exact(second.clone(), response.clone(), 300, None);
    let first_id = service.entry_id(&first).unwrap();
    let second_id = service.entry_id(&second).unwrap();
    let (first_entered, _first_release) = persister.gate_next_flush();
    let first_task = {
        let service = service.clone();
        tokio::spawn(async move { service.invalidate(CacheInvalidation::Id(first_id)).await })
    };
    tokio::time::timeout(Duration::from_secs(2), first_entered.notified())
        .await
        .unwrap();
    let (second_entered, second_release) = persister.gate_next_flush();
    let second_task = {
        let service = service.clone();
        tokio::spawn(async move { service.invalidate(CacheInvalidation::Id(second_id)).await })
    };
    tokio::task::yield_now().await;
    assert!(service.entry_id(&second).is_some());
    let during = service.publication_epoch();
    assert!(
        service
            .put_exact_if_current(during, first.clone(), response.clone(), 300, None)
            .is_none()
    );
    first_task.abort();
    assert!(first_task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(2), second_entered.notified())
        .await
        .unwrap();
    assert!(
        service
            .put_exact_if_current(
                service.publication_epoch(),
                first.clone(),
                response.clone(),
                300,
                None
            )
            .is_none()
    );
    second_release.add_permits(1);
    assert_eq!(second_task.await.unwrap().unwrap().deleted, 1);
    assert!(
        service
            .put_exact_if_current(old_epoch, first.clone(), response.clone(), 300, None)
            .is_none()
    );
    assert!(
        service
            .put_exact_if_current(during, first.clone(), response.clone(), 300, None)
            .is_none()
    );
    assert!(
        service
            .put_exact_if_current(
                service.publication_epoch(),
                first.clone(),
                response,
                300,
                None
            )
            .is_some()
    );
    persister.shutdown().await.unwrap();
    let rows = db.load_dns().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, codec::key_suffix(&first));
}

#[tokio::test]
async fn invalidation_reports_database_failure_and_does_not_publish_old_work() {
    let dir = tempfile::tempdir().unwrap();
    let db = test_db(&dir);
    let (key, response, _) = fixture(IngressProfile::Internal, None, upstream("default"));
    let encoded = codec::encode(&key, &response, unix_now() + 300);
    db.write_dns(vec![(encoded.suffix, unix_now() + 300, encoded.bytes)])
        .unwrap();
    let persister = DnsCachePersister::spawn(db.clone());
    let mut cache = DnsCache::new(8);
    cache.set_persister(Some(persister.clone()));
    let service = cache.service();
    let epoch = service.publication_epoch();
    db.set_query_only_for_test(true);
    let result = service
        .invalidate(CacheInvalidation::Name {
            name: "example.com".into(),
            types: vec![],
        })
        .await;
    assert!(matches!(result, Err(PersistControlError::Database(_))));
    assert!(
        service
            .put_exact_if_current(epoch, key.clone(), response.clone(), 300, None)
            .is_none()
    );
    assert_eq!(db.load_dns().unwrap().len(), 1);
    db.set_query_only_for_test(false);
    assert!(
        service
            .put_exact_if_current(service.publication_epoch(), key, response, 300, None)
            .is_some()
    );
    service.invalidate(CacheInvalidation::All).await.unwrap();
    assert!(db.load_dns().unwrap().is_empty());
    persister.shutdown().await.unwrap();
}
