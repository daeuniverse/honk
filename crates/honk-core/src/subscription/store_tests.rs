use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::*;

const MIB: usize = 1024 * 1024;

fn subscription(name: &str) -> Subscription {
    Subscription {
        url: format!("https://example.invalid/{name}"),
        ..Default::default()
    }
}

fn filler(bytes: usize) -> String {
    "#".repeat(bytes)
}

#[tokio::test]
async fn a_body_survives_restart() {
    let temp = tempfile::tempdir().unwrap();
    let sub = subscription("a");
    SubscriptionStore::in_dir(temp.path())
        .store_content(&sub, "socks5://127.0.0.1:1080#stored".into())
        .await
        .unwrap();
    let reopened = SubscriptionStore::in_dir(temp.path());
    assert_eq!(
        reopened.load_nodes(&sub).await.unwrap().unwrap()[0].name,
        "stored"
    );
}

#[tokio::test]
async fn a_subscription_with_cache_off_is_neither_stored_nor_restored_nor_kept() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let mut sub = subscription("a");
    store
        .store_content(&sub, "socks5://127.0.0.1:1080#stored".into())
        .await
        .unwrap();
    sub.cache = false;
    assert!(store.load_nodes(&sub).await.unwrap().is_none());
    store.remove_body(&sub);
    store
        .store_content(&sub, "socks5://127.0.0.1:1080#fresh".into())
        .await
        .unwrap();
    assert!(store.body(&sub).is_none());
    let kept = subscription("b");
    store.set_enabled([&sub, &kept]);
    assert_eq!(
        *store.state().enabled_subscriptions(),
        Some([SubscriptionStore::key(&kept)].into())
    );
}

#[tokio::test]
async fn a_replacement_url_frees_the_old_bodies() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let old: Vec<_> = (0..4)
        .map(|index| subscription(&format!("old{index}")))
        .collect();
    store.set_enabled(&old);
    for sub in &old {
        store
            .store_content(sub, filler(7 * MIB + MIB / 2))
            .await
            .unwrap();
    }
    let replacement = subscription("new");
    store.set_enabled([&replacement]);
    store
        .store_content(&replacement, filler(4 * MIB))
        .await
        .unwrap();
    assert!(old.iter().all(|sub| store.body(sub).is_none()));
    assert_eq!(store.body(&replacement).unwrap().len(), 4 * MIB);
}

#[tokio::test]
async fn a_write_past_the_cap_among_enabled_bodies_is_refused_and_keeps_the_old_body() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let full: Vec<_> = (0..4)
        .map(|index| subscription(&format!("full{index}")))
        .collect();
    let last = subscription("last");
    store.set_enabled(full.iter().chain([&last]));
    for sub in &full {
        store
            .store_content(sub, filler(7 * MIB + MIB / 2))
            .await
            .unwrap();
    }
    store
        .store_content(&last, "socks5://127.0.0.1:1080#old".into())
        .await
        .unwrap();
    let mut diagnostics = Vec::new();
    SubscriptionManager::persist_content(&last, Some(&store), filler(4 * MIB), &mut diagnostics, 0)
        .await;
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "subscription-store-write-failed")
    );
    assert_eq!(
        store.body(&last).as_deref(),
        Some("socks5://127.0.0.1:1080#old")
    );
    assert!(full.iter().all(|sub| store.body(sub).is_some()));
}

#[tokio::test]
async fn two_subscriptions_refreshed_in_turn_both_keep_their_bodies() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let removed: Vec<_> = (0..3)
        .map(|index| subscription(&format!("removed{index}")))
        .collect();
    store.set_enabled(&removed);
    for sub in &removed {
        store
            .store_content(sub, filler(7 * MIB + MIB / 2))
            .await
            .unwrap();
    }
    let (a, b) = (subscription("a"), subscription("b"));
    store.set_enabled([&a, &b]);
    // Each refresh handles one subscription; the second one needs room.
    store
        .store_content(&a, filler(7 * MIB + MIB / 2))
        .await
        .unwrap();
    store
        .store_content(&b, filler(7 * MIB + MIB / 2))
        .await
        .unwrap();
    assert!(store.body(&a).is_some() && store.body(&b).is_some());
    assert!(removed.iter().all(|sub| store.body(sub).is_none()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_write_cannot_evict_a_newly_enabled_body() {
    use std::sync::{Barrier, LazyLock};

    static BUSY: LazyLock<Barrier> = LazyLock::new(|| Barrier::new(2));

    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let full: Vec<_> = (0..4)
        .map(|index| subscription(&format!("full{index}")))
        .collect();
    let body = filler(8 * MIB);
    for sub in &full {
        store.store_content(sub, body.clone()).await.unwrap();
    }
    store.set_enabled(&full[1..]);
    let mut blocker = store.state().connect(crate::state::Class::Strict).unwrap();
    let transaction = blocker
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    store
        .state()
        .strict()
        .busy_handler(Some(|attempt| {
            if attempt != 0 {
                return false;
            }
            BUSY.wait();
            BUSY.wait();
            true
        }))
        .unwrap();
    let writer = store.clone();
    let write = tokio::spawn(async move {
        writer
            .store_content(&subscription("replacement"), "#".into())
            .await
    });

    BUSY.wait();
    store.set_enabled(&full);
    drop(transaction);
    BUSY.wait();

    assert!(write.await.unwrap().is_err());
    assert_eq!(store.body(&full[0]).as_deref(), Some(body.as_str()));
    assert!(store.body(&subscription("replacement")).is_none());
}

fn legacy_directory(root: &Path, bodies: &[(&Subscription, String)]) {
    fs::create_dir(root).unwrap();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    for (sub, body) in bodies {
        let path = root.join(SubscriptionStore::key(sub));
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(root.join(".left.123.tmp"), b"partial").unwrap();
}

#[tokio::test]
async fn legacy_bodies_are_copied_at_open_and_removed_only_by_remove() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join(".sub");
    let (kept, orphan) = (subscription("kept"), subscription("orphan"));
    legacy_directory(
        &root,
        &[
            (&kept, "socks5://127.0.0.1:1080#legacy".into()),
            (&orphan, "socks5://127.0.0.1:1080#orphan".into()),
        ],
    );
    let store = SubscriptionStore::in_dir(temp.path());
    let legacy =
        LegacySubscriptionStore::import(store.state(), [root.clone()], std::slice::from_ref(&kept))
            .unwrap();
    assert_eq!(
        store.load_nodes(&kept).await.unwrap().unwrap()[0].name,
        "legacy"
    );
    assert!(store.body(&orphan).is_none());
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        3,
        "nothing removed before the lock"
    );

    legacy.remove();
    assert_eq!(
        fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>(),
        [SubscriptionStore::key(&orphan)],
        "a body that was not copied stays"
    );
}

#[tokio::test]
async fn a_disabled_legacy_body_is_imported_when_a_later_start_enables_it() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join(".sub");
    let (on, mut off) = (subscription("on"), subscription("off"));
    legacy_directory(
        &root,
        &[
            (&on, "socks5://127.0.0.1:1080#on".into()),
            (&off, "socks5://127.0.0.1:1080#off".into()),
        ],
    );
    off.enabled = false;
    let store = SubscriptionStore::in_dir(temp.path());
    LegacySubscriptionStore::import(store.state(), [root.clone()], &[on.clone(), off.clone()])
        .unwrap()
        .remove();
    assert!(store.body(&off).is_none());
    drop(store);

    // Restart without network, with the subscription enabled again.
    off.enabled = true;
    let store = SubscriptionStore::in_dir(temp.path());
    LegacySubscriptionStore::import(store.state(), [root.clone()], &[on.clone(), off.clone()])
        .unwrap()
        .remove();
    assert_eq!(
        store.load_nodes(&off).await.unwrap().unwrap()[0].name,
        "off"
    );
    assert!(!root.exists());
}

#[tokio::test]
async fn a_legacy_import_stops_at_the_cap_and_skips_an_unsafe_directory() {
    let temp = tempfile::tempdir().unwrap();
    let writable = temp.path().join("writable");
    fs::create_dir(&writable).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
    let root = temp.path().join("secure");
    let subs: Vec<_> = (0..5)
        .map(|index| subscription(&format!("s{index}")))
        .collect();
    let bodies: Vec<_> = subs
        .iter()
        .map(|sub| (sub, filler(7 * MIB + MIB / 2)))
        .collect();
    legacy_directory(&root, &bodies);
    let store = SubscriptionStore::in_dir(temp.path());
    LegacySubscriptionStore::import(store.state(), [writable.clone(), root.clone()], &subs)
        .unwrap()
        .remove();
    let stored = subs.iter().filter(|sub| store.body(sub).is_some()).count();
    assert_eq!(stored, 4, "32 MiB holds four bodies of 7.5 MiB");
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        1,
        "the body left behind stays"
    );
    assert_eq!(
        fs::metadata(writable).unwrap().permissions().mode() & 0o7777,
        0o777
    );
}

#[tokio::test]
async fn a_legacy_body_that_cannot_be_copied_stays_for_a_retry() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join(".sub");
    let (large, small) = (subscription("large"), subscription("small"));
    legacy_directory(
        &root,
        &[
            (&large, filler(8 * MIB + 1)),
            (&small, "socks5://127.0.0.1:1080#small".into()),
        ],
    );
    let store = SubscriptionStore::in_dir(temp.path());
    let subscriptions = [large.clone(), small.clone()];
    let import = || LegacySubscriptionStore::import(store.state(), [root.clone()], &subscriptions);
    import().unwrap().remove();
    assert!(store.body(&large).is_none());
    assert_eq!(
        store.body(&small).as_deref(),
        Some("socks5://127.0.0.1:1080#small")
    );
    assert!(root.join(SubscriptionStore::key(&large)).exists());
    assert!(!root.join(SubscriptionStore::key(&small)).exists());
    // A later start retries; once every body is copied, the store goes.
    fs::write(
        root.join(SubscriptionStore::key(&large)),
        "socks5://127.0.0.1:1080#large",
    )
    .unwrap();
    import().unwrap().remove();
    assert_eq!(
        store.body(&large).as_deref(),
        Some("socks5://127.0.0.1:1080#large")
    );
    assert!(!root.exists());
}
