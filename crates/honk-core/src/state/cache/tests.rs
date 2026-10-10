use super::*;
use std::time::Duration;

fn member(name: &str) -> SelectorMember {
    SelectorMember::Group(name.to_owned())
}

#[test]
fn selector_and_clash_state_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    assert!(
        db.load_network_selector("proxy", SelectionNetwork::Tcp)
            .is_none()
    );
    db.save_network_selector("proxy", SelectionNetwork::Tcp, &member("a"));
    db.save_network_selector("proxy", SelectionNetwork::Udp, &member("b"));
    db.save_clash_mode("Global");
    db.save_clash_global("proxy");
    db.flush_pending().unwrap();
    drop(db);

    let db = CacheDb::in_dir(directory.path());
    for (network, expected) in [(SelectionNetwork::Tcp, "a"), (SelectionNetwork::Udp, "b")] {
        assert_eq!(
            db.load_network_selector("proxy", network).unwrap().unwrap(),
            member(expected)
        );
    }
    assert_eq!(db.load_clash_mode().as_deref(), Some("Global"));
    assert_eq!(db.load_clash_global().as_deref(), Some("proxy"));
}

#[test]
fn writer_keeps_the_directory_locked_after_the_cache_reader_closes() {
    use nix::fcntl::{Flock, FlockArg};

    let directory = tempfile::tempdir().unwrap();
    let state = Arc::new(StateDb::open(directory.path()).unwrap());
    let db = CacheDb::open(Arc::clone(&state)).unwrap();
    let writer = db.writer.clone();
    drop(state);
    drop(db);

    let lock = || {
        Flock::lock(
            std::fs::File::open(directory.path().join(super::super::STATE_DIR)).unwrap(),
            FlockArg::LockExclusiveNonblock,
        )
    };
    assert!(matches!(lock(), Err((_, nix::errno::Errno::EWOULDBLOCK))));
    let (ack, result) = mpsc::channel();
    writer.send(Write::Barrier(ack)).unwrap();
    result
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    drop(writer);

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match lock() {
            Ok(guard) => {
                drop(guard);
                break;
            }
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "writer did not release its database lock"
                );
                std::thread::yield_now();
            }
            Err((_, error)) => panic!("exclusive state lock failed: {error}"),
        }
    }
}

#[test]
fn point_writes_are_latest_wins_without_blocking_readers() {
    let directory = tempfile::tempdir().unwrap();
    let db = Arc::new(CacheDb::in_dir(directory.path()));
    let writer = Arc::clone(&db);
    let worker = std::thread::spawn(move || {
        for value in 0..10_000 {
            writer.save_clash_global(&value.to_string());
        }
    });
    for _ in 0..10_000 {
        let _ = db.load_clash_global();
    }
    worker.join().unwrap();
    assert_eq!(db.load_clash_global().as_deref(), Some("9999"));
}

#[test]
fn point_save_does_not_wait_for_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let db = Arc::new(CacheDb::in_dir(directory.path()));
    let writer_guard = db.lock_for_test();
    let (completed, completion) = mpsc::channel();
    let saving = Arc::clone(&db);
    let worker = std::thread::spawn(move || {
        saving.save_clash_global("node-a");
        completed.send(()).unwrap();
    });

    completion
        .recv_timeout(std::time::Duration::from_millis(100))
        .expect("point save must not wait for SQLite");
    assert_eq!(db.load_clash_global().as_deref(), Some("node-a"));
    drop(writer_guard);
    worker.join().unwrap();
    db.flush_pending().unwrap();
}

#[test]
fn periodic_flush_bounds_point_write_durability() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    db.save_clash_mode("Direct");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        let stored = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM clash_state WHERE key = 'mode'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok();
        if stored.as_deref() == Some("Direct") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "periodic flush exceeded durability bound"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn delay_sample_save_load_and_age_out() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    let now = 1_700_000_000u64;

    db.save_delay_samples(vec![
        ("node-a".into(), 123, now - 60),
        ("node-old".into(), 456, now - 25 * 3600),
    ]);
    db.flush_pending().unwrap();
    let barrier = |db: &CacheDb| db.request(Write::Barrier).unwrap();
    barrier(&db);

    let samples = db.load_delay_samples(now, 24 * 3600);
    assert_eq!(samples, [("node-a".to_string(), 123, now - 60)]);
    barrier(&db);
    let rows: i64 = db
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM delay_sample", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1, "the stale sample is deleted");
}

#[test]
fn dns_rows_write_load_and_flush_without_touching_other_tables() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    db.save_clash_global("proxy");
    db.write_dns(vec![("opaque".into(), 1_000, vec![0, 255, 1])])
        .unwrap();
    assert_eq!(db.load_dns().unwrap(), [("opaque".into(), vec![0, 255, 1])]);
    db.delete_dns_entries(&["other".into()]).unwrap();
    assert_eq!(db.load_dns().unwrap().len(), 1);

    db.flush_dns().unwrap();
    assert!(db.load_dns().unwrap().is_empty());
    assert_eq!(db.load_clash_global().as_deref(), Some("proxy"));
}

#[test]
fn sqlite_errors_carry_only_the_result_code() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    let error = db
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO clash_state (key, value) VALUES ('secret-key', 'secret-value')",
            [],
        )
        .unwrap_err();
    let text = CacheDbError::from(error).to_string();
    assert!(
        text.contains(&rusqlite::ffi::SQLITE_CONSTRAINT_CHECK.to_string()),
        "{text}"
    );
    assert!(
        !text.contains("secret") && !text.contains("CHECK"),
        "{text}"
    );
}

#[test]
fn an_idle_cache_does_not_wake_the_flusher() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    let wakeups = || db.flush.wakeups.load(std::sync::atomic::Ordering::Relaxed);
    std::thread::sleep(std::time::Duration::from_millis(350));
    assert_eq!(wakeups(), 0, "the flusher woke with nothing pending");

    db.save_clash_mode("Direct");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while db
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM clash_state", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
        == 0
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the write was not flushed"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    std::thread::sleep(std::time::Duration::from_millis(350));
    assert_eq!(wakeups(), 1, "one write, one wakeup");
}

#[test]
fn dns_rows_are_capped_by_evicting_the_earliest_expiry() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    let rows: Vec<DnsRow> = (0..5000u64)
        .map(|index| (format!("k{index}"), 10_000 + index, vec![0]))
        .collect();
    for batch in rows.chunks(1000) {
        db.write_dns(batch.to_vec()).unwrap();
    }
    let (count, earliest): (i64, i64) = db
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*), min(expire_at) FROM dns_answer",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (count, earliest),
        (MAX_DNS_ROWS, 10_000 + 5000 - MAX_DNS_ROWS)
    );
}

#[cfg(feature = "native-api")]
#[test]
fn cache_writes_stop_at_the_budget_so_a_large_revision_still_commits() {
    use crate::native_api::store::db::DbStore;
    use honk_config::parser::{SourceLimits, parse_dae_sources};

    let directory = tempfile::tempdir().unwrap();
    // 32 MiB ceiling: an 8 MiB budget for cache writes and 24 MiB for strict ones.
    let state = Arc::new(StateDb::open_for_test(directory.path(), 8192));
    let db = CacheDb::open(Arc::clone(&state)).unwrap();
    // Rows with a 64-hex key and an entry near 4 KiB spill to an overflow
    // page: 4096 of them take about 18 MiB.
    for batch in 0..8u64 {
        let rows = (0..512u64)
            .map(|index| {
                (
                    format!("{batch:032x}{index:032x}"),
                    10_000 + index,
                    vec![7; 4050],
                )
            })
            .collect();
        db.write_dns(rows).unwrap();
    }

    let entry = directory.path().join("etc/config.dae");
    let store = DbStore::open(Arc::clone(&state), &entry).unwrap();
    let initial = parse_dae_sources(
        &[(entry.clone(), Arc::from("global {}\n"))],
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap()
    .sources;
    let none = crate::native_api::config::ListenerSecrets::new(&[], "");
    store
        .initialize(&initial, &none, &Default::default(), "startup")
        .unwrap();
    // Just under 16 MiB of stored JSON once every quote is escaped.
    let content = format!("global {{}}\n# {}\n", "\"".repeat(8_380_000));
    let candidate = parse_dae_sources(
        &[(entry.clone(), Arc::from(content.as_str()))],
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap()
    .sources;
    let pin = store.pin(&entry).unwrap();
    let pending = store
        .commit(pin, &content, &candidate, "control", Box::new(|| Ok(())))
        .unwrap();
    assert_eq!(store.promote(pending), Ok(2));
    let rows: i64 = db
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM dns_answer", [], |row| row.get(0))
        .unwrap();
    assert!(rows < MAX_DNS_ROWS, "the budget prunes DNS rows: {rows}");
}

#[test]
fn a_tick_returns_a_bounded_number_of_free_pages() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    let rows: Vec<DnsRow> = (0..1000u64)
        .map(|index| (format!("{index:064}"), u64::MAX / 2, vec![7; 3000]))
        .collect();
    db.write_dns(rows).unwrap();
    db.flush_dns().unwrap();
    let free = |db: &CacheDb| -> i64 {
        db.conn
            .lock()
            .unwrap()
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))
            .unwrap()
    };
    let before = free(&db);
    assert!(before > 2 * super::super::VACUUM_PAGES);
    db.maintain(Maintenance::default()).unwrap();
    assert_eq!(free(&db), before - super::super::VACUUM_PAGES);
}

#[test]
fn a_batch_that_would_cross_the_budget_is_rolled_back() {
    let directory = tempfile::tempdir().unwrap();
    // A 256-page (1 MiB) budget for cache writes.
    let state = Arc::new(StateDb::open_for_test(
        directory.path(),
        super::super::STRICT_HEADROOM_PAGES + 256,
    ));
    let db = CacheDb::open(Arc::clone(&state)).unwrap();
    let used = |db: &CacheDb| super::super::used_pages(&db.conn.lock().unwrap()).unwrap();
    let row = |index: u64| (format!("{index:064}"), 10_000 + index, vec![7; 3000]);
    let mut next = 0;
    while used(&db) < 240 {
        assert_eq!(db.write_dns(vec![row(next)]).unwrap(), DnsWrite::Written);
        next += 1;
    }

    let delays = (0..2000)
        .map(|index| (format!("{index:0200}"), 10, 1_000))
        .collect();
    db.save_delay_samples(delays);
    // Any request queued behind the batch waits for it.
    db.delete_dns_entries(&[]).unwrap();
    assert!(db.delay_nodes().unwrap().is_empty());
    assert!(used(&db) <= 256, "{} pages", used(&db));

    let batch = (next..next + 64).map(row).collect();
    assert_eq!(db.write_dns(batch).unwrap(), DnsWrite::Skipped);
    assert!(used(&db) <= 256, "{} pages", used(&db));
}

#[test]
fn a_dropped_group_and_node_keep_their_rows_for_one_tick() {
    let directory = tempfile::tempdir().unwrap();
    let state = Arc::new(StateDb::open(directory.path()).unwrap());
    let db = CacheDb::open(Arc::clone(&state)).unwrap();
    let now = 1_700_000_000;
    for group in ["kept", "dropped"] {
        db.save_network_selector(group, SelectionNetwork::Tcp, &member("m"));
    }
    db.save_delay_samples(vec![
        ("kept-node".into(), 5, now),
        ("dropped-node".into(), 5, now),
    ]);
    db.write_dns(vec![
        ("expired".into(), now - 1, vec![0]),
        ("fresh".into(), now + 60, vec![0]),
    ])
    .unwrap();
    db.maintain(Maintenance::default()).unwrap();
    let live = Live {
        selector_groups: HashSet::from(["kept".to_owned()]),
        nodes: HashSet::from(["kept-node".to_owned()]),
    };
    let rows = |db: &CacheDb| {
        let mut groups = db.selector_groups().unwrap();
        let mut nodes = db.delay_nodes().unwrap();
        groups.sort();
        nodes.sort();
        let dns: Vec<String> = db
            .load_dns()
            .unwrap()
            .into_iter()
            .map(|row| row.0)
            .collect();
        (groups, nodes, dns)
    };
    let mut missing = Missing::default();
    let owners = TickOwners {
        store_dns: true,
        store_subscribe: false,
    };

    maintenance_tick(
        &state,
        Some(&db),
        &live,
        Vec::new(),
        &mut missing,
        owners,
        now,
    );
    assert_eq!(
        rows(&db),
        (
            vec!["dropped".to_owned(), "kept".to_owned()],
            vec!["dropped-node".to_owned(), "kept-node".to_owned()],
            vec!["fresh".to_owned()],
        )
    );
    maintenance_tick(
        &state,
        Some(&db),
        &live,
        Vec::new(),
        &mut missing,
        owners,
        now,
    );
    assert_eq!(
        rows(&db),
        (
            vec!["kept".to_owned()],
            vec!["kept-node".to_owned()],
            vec!["fresh".to_owned()],
        )
    );
}

#[tokio::test]
async fn a_disabled_subscription_keeps_its_body_for_one_tick() {
    let directory = tempfile::tempdir().unwrap();
    let state = Arc::new(StateDb::open(directory.path()).unwrap());
    let store = crate::subscription::SubscriptionStore::new(Arc::clone(&state));
    let subscription = |name: &str| honk_config::subscription::Subscription {
        url: format!("https://example.invalid/{name}"),
        ..Default::default()
    };
    let (kept, dropped) = (subscription("kept"), subscription("dropped"));
    for sub in [&kept, &dropped] {
        store.store_content(sub, "body".into()).await.unwrap();
    }
    store.set_enabled([&kept]);
    let live = Live {
        selector_groups: HashSet::new(),
        nodes: HashSet::new(),
    };
    let owners = TickOwners {
        store_dns: false,
        store_subscribe: true,
    };
    let mut missing = Missing::default();
    let bodies = || -> i64 {
        state
            .strict()
            .query_row("SELECT count(*) FROM subscription_body", [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    maintenance_tick(&state, None, &live, Vec::new(), &mut missing, owners, 0);
    assert_eq!(bodies(), 2);
    maintenance_tick(&state, None, &live, Vec::new(), &mut missing, owners, 0);
    let remaining: String = state
        .strict()
        .query_row("SELECT key FROM subscription_body", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        remaining,
        crate::subscription::SubscriptionStore::key(&kept)
    );
}
