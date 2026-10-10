use std::fs;

use super::*;

fn db_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STATE_DIR).join(DB_FILE)
}

fn read_pragmas(connection: &Connection) -> Vec<(&'static str, String)> {
    [
        "journal_mode",
        "wal_autocheckpoint",
        "journal_size_limit",
        "cache_size",
        "mmap_size",
        "max_page_count",
        "synchronous",
        "foreign_keys",
        "busy_timeout",
        "page_size",
        "auto_vacuum",
        "application_id",
        "user_version",
    ]
    .into_iter()
    .map(|name| {
        let value = connection
            .query_row(&format!("PRAGMA {name}"), [], |row| {
                row.get::<_, rusqlite::types::Value>(0)
            })
            .unwrap();
        (name, format!("{value:?}"))
    })
    .collect()
}

#[test]
fn pragmas_read_back_on_a_fresh_and_a_reopened_file() {
    let directory = tempfile::tempdir().unwrap();
    let expected: Vec<(&str, String)> = [
        ("journal_mode", "Text(\"wal\")"),
        ("wal_autocheckpoint", "Integer(256)"),
        ("journal_size_limit", "Integer(1048576)"),
        ("cache_size", "Integer(-256)"),
        ("mmap_size", "Integer(0)"),
        ("max_page_count", "Integer(28672)"),
        ("synchronous", "Integer(2)"),
        ("foreign_keys", "Integer(1)"),
        ("busy_timeout", "Integer(2000)"),
        ("page_size", "Integer(4096)"),
        ("auto_vacuum", "Integer(2)"),
        ("application_id", "Integer(1752133227)"),
        ("user_version", "Integer(3)"),
    ]
    .into_iter()
    .map(|(name, value)| (name, value.to_owned()))
    .collect();
    let state = StateDb::open(directory.path()).unwrap();
    assert_eq!(read_pragmas(&state.strict()), expected);
    drop(state);
    let state = StateDb::open(directory.path()).unwrap();
    assert_eq!(read_pragmas(&state.strict()), expected);
}

/// The bundled SQLite is built with `SQLITE_ENABLE_MEMORY_MANAGEMENT`, so every
/// connection's page cache draws on one process-wide budget, the sum of their
/// `cache_size`. Other tests' connections would lend this one room, so the
/// measurement runs in a child process holding only this connection.
#[test]
fn page_cache_stays_within_cache_size() {
    const CHILD: &str = "HONK_STATE_CACHE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "state::tests::page_cache_stays_within_cache_size",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && text.contains("1 passed"),
            "{text}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    StateDb::open(directory.path())
        .unwrap()
        .strict()
        .execute_batch(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 4096)
             INSERT INTO main.subscription_body (key, fetched_at, body)
               SELECT 'k' || i, 0, randomblob(1024) FROM n;",
        )
        .unwrap();
    let state = StateDb::open(directory.path()).unwrap();
    let connection = state.strict();
    let total: i64 = connection
        .query_row(
            "SELECT sum(length(hex(body))) FROM subscription_body",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(total, 4096 * 2048);
    let (mut used, mut highwater) = (0, 0);
    // SAFETY: the handle is live for the borrow of `connection`, and the
    // out-pointers are valid locals.
    let status = unsafe {
        rusqlite::ffi::sqlite3_db_status(
            connection.handle(),
            rusqlite::ffi::SQLITE_DBSTATUS_CACHE_USED,
            &mut used,
            &mut highwater,
            0,
        )
    };
    assert_eq!(status, rusqlite::ffi::SQLITE_OK);
    // SQLite also counts page headers and allocator rounding, and the process
    // page-cache group lets one cache run a little past its own limit under
    // load (up to about 390 KiB measured); the default cache reaches about 2 MiB.
    assert!(used <= 512 * 1024, "cache used {used}");
}

#[test]
fn created_directory_and_file_are_private() {
    let directory = tempfile::tempdir().unwrap();
    drop(StateDb::open(directory.path()).unwrap());
    let state = fs::metadata(directory.path().join(STATE_DIR)).unwrap();
    let file = fs::symlink_metadata(db_path(directory.path())).unwrap();
    assert!(state.is_dir() && file.is_file());
    assert_eq!(state.permissions().mode() & 0o777, 0o700);
    assert_eq!(file.permissions().mode() & 0o777, 0o600);

    // Owned and only readable by others: tightened in place.
    fs::set_permissions(db_path(directory.path()), fs::Permissions::from_mode(0o640)).unwrap();
    drop(StateDb::open(directory.path()).unwrap());
    let file = fs::metadata(db_path(directory.path())).unwrap();
    assert_eq!(file.permissions().mode() & 0o777, 0o600);
    let state = directory.path().join(STATE_DIR);
    fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
    drop(StateDb::open(directory.path()).unwrap());
    let mode = fs::metadata(&state).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);

    // Writable by others: refused and left alone.
    fs::set_permissions(db_path(directory.path()), fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(
        StateDb::open(directory.path()).err(),
        Some(StateError::Unsafe(Refusal::new(
            Target::Database,
            Rule::GroupOrOtherBits
        )))
    );
    let file = fs::metadata(db_path(directory.path())).unwrap();
    assert_eq!(file.permissions().mode() & 0o777, 0o660);
    fs::set_permissions(db_path(directory.path()), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        StateDb::open(directory.path()).err(),
        Some(StateError::Unsafe(Refusal::new(
            Target::StateDir,
            Rule::GroupOrOtherBits
        )))
    );
}

#[cfg(feature = "native-api")]
#[test]
fn readers_refuse_readable_modes_and_leave_them() {
    let directory = tempfile::tempdir().unwrap();
    drop(StateDb::open(directory.path()).unwrap());
    let state = directory.path().join(STATE_DIR);
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;

    fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        open_read_only(directory.path()).err(),
        Some(StateError::Unsafe(Refusal::new(
            Target::StateDir,
            Rule::GroupOrOtherBits
        )))
    );
    assert_eq!(mode(&state), 0o750);

    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(db_path(directory.path()), fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(
        open_read_only(directory.path()).err(),
        Some(StateError::Unsafe(Refusal::new(
            Target::Database,
            Rule::GroupOrOtherBits
        )))
    );
    assert_eq!(mode(&db_path(directory.path())), 0o640);

    drop(StateDb::open(directory.path()).unwrap());
    assert_eq!(mode(&db_path(directory.path())), 0o600);
    assert!(open_read_only(directory.path()).is_ok());
}

#[test]
fn symlinked_state_directory_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), directory.path().join(STATE_DIR)).unwrap();
    assert_eq!(
        StateDb::open(directory.path()).err(),
        Some(StateError::Unsafe(Refusal::new(
            Target::StateDir,
            Rule::Symlink
        )))
    );
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn symlinked_database_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join(STATE_DIR);
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let target = directory.path().join("target.db");
    fs::write(&target, b"").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, db_path(directory.path())).unwrap();
    assert_eq!(
        StateDb::open(directory.path()).err(),
        Some(StateError::Unsafe(Refusal::new(
            Target::Database,
            Rule::Symlink
        )))
    );
    assert_eq!(fs::read(&target).unwrap(), b"");
}

#[test]
fn corrupt_database_is_refused_and_kept() {
    let directory = tempfile::tempdir().unwrap();
    drop(StateDb::open(directory.path()).unwrap());
    let garbage = vec![0x5a; 8192];
    fs::write(db_path(directory.path()), &garbage).unwrap();
    let wal = directory.path().join(STATE_DIR).join("honk.db-wal");
    fs::write(&wal, b"wal").unwrap();
    assert_eq!(
        StateDb::open(directory.path()).err(),
        Some(StateError::Corrupt)
    );
    assert_eq!(fs::read(db_path(directory.path())).unwrap(), garbage);
    assert_eq!(fs::read(&wal).unwrap(), b"wal");
}

#[test]
fn foreign_or_newer_databases_are_refused() {
    for (application_id, version) in [(1, 0), (1, 1), (APPLICATION_ID, SCHEMA_VERSION + 1)] {
        let directory = tempfile::tempdir().unwrap();
        drop(StateDb::open(directory.path()).unwrap());
        let path = db_path(directory.path());
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(&format!(
                "CREATE TABLE other (x); PRAGMA application_id = {application_id}; PRAGMA user_version = {version};"
            ))
            .unwrap();
        drop(connection);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            StateDb::open(directory.path()).err(),
            Some(StateError::Unsupported),
            "{application_id} {version}"
        );
    }
}

/// Runs `probe` in a child process against this test's db and reports
/// whether this process still holds SQLite's shared lock on it; the child
/// then opens and closes the db as another honk process would.
fn lock_probe(test: &str, data_dir: &Path) -> String {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env(LOCK_PROBE, data_dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

const LOCK_PROBE: &str = "HONK_STATE_LOCK_PROBE";

/// In the child: the probe itself. `true` when it ran.
fn run_lock_probe() -> bool {
    let Some(data_dir) = std::env::var_os(LOCK_PROBE) else {
        return false;
    };
    // SQLite's shared-lock byte range on the database file.
    let file = fs::File::open(db_path(Path::new(&data_dir))).unwrap();
    let mut probe = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0x4000_0002,
        l_len: 510,
        l_pid: 0,
    };
    // SAFETY: `probe` is a valid flock for F_GETLK on a live descriptor.
    assert_eq!(
        unsafe {
            libc::fcntl(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::F_GETLK,
                &mut probe,
            )
        },
        0
    );
    println!(
        "SHARED-HELD={}",
        probe.l_type != libc::F_UNLCK as libc::c_short
    );
    drop(StateDb::open(Path::new(&data_dir)).unwrap());
    true
}

fn written_wal(state: &StateDb, data_dir: &Path) -> PathBuf {
    state
        .strict()
        .execute(
            "INSERT INTO legacy_import (source, done_at) VALUES ('kept', 1)",
            [],
        )
        .unwrap();
    let wal = data_dir.join(STATE_DIR).join("honk.db-wal");
    assert!(fs::metadata(&wal).unwrap().len() > 0);
    wal
}

/// Another process that opens and closes the db must see this process's
/// connection: if closing our own descriptor dropped SQLite's POSIX locks, the
/// other process could close as the last connection and delete the `-wal`.
#[test]
fn another_process_closing_the_db_keeps_the_wal_of_an_open_one() {
    if run_lock_probe() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let state = StateDb::open(directory.path()).unwrap();
    let wal = written_wal(&state, directory.path());
    let stdout = lock_probe(
        "state::tests::another_process_closing_the_db_keeps_the_wal_of_an_open_one",
        directory.path(),
    );
    assert!(
        stdout.contains("SHARED-HELD=true"),
        "this process lost its SQLite lock on the database file"
    );
    assert!(wal.exists(), "the other process deleted the open db's -wal");
}

/// A reader opened inside the daemon, as offline validation does, must not
/// release the daemon's own locks when its checks close their descriptor.
#[cfg(feature = "native-api")]
#[test]
fn a_reader_inside_the_daemon_keeps_its_locks() {
    if run_lock_probe() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let state = StateDb::open(directory.path()).unwrap();
    let wal = written_wal(&state, directory.path());
    drop(open_read_only(directory.path()).unwrap());
    let stdout = lock_probe(
        "state::tests::a_reader_inside_the_daemon_keeps_its_locks",
        directory.path(),
    );
    assert!(
        stdout.contains("SHARED-HELD=true"),
        "the reader's descriptor released this process's SQLite lock"
    );
    assert!(wal.exists());
    let rows: i64 = state
        .strict()
        .query_row("SELECT count(*) FROM legacy_import", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1);
}

fn corrupt_with_wal(data_dir: &Path) {
    drop(StateDb::open(data_dir).unwrap());
    fs::write(db_path(data_dir), vec![0x5a; 8192]).unwrap();
    fs::write(data_dir.join(STATE_DIR).join("honk.db-wal"), b"wal").unwrap();
    assert_eq!(StateDb::open(data_dir).err(), Some(StateError::Corrupt));
}

#[test]
fn reset_moves_a_corrupt_db_aside_with_its_wal() {
    let directory = tempfile::tempdir().unwrap();
    corrupt_with_wal(directory.path());
    let state = reset_corrupt(directory.path()).unwrap().expect("a new db");
    let dir = directory.path().join(STATE_DIR);
    assert_eq!(
        fs::read(dir.join("honk.db.corrupt")).unwrap(),
        vec![0x5a; 8192]
    );
    assert_eq!(fs::read(dir.join("honk.db.corrupt-wal")).unwrap(), b"wal");
    assert_eq!(pragma(&state.strict(), "user_version"), Ok(SCHEMA_VERSION));
}

#[test]
fn reset_keeps_an_earlier_corrupt_copy_and_runs_without_a_db() {
    let directory = tempfile::tempdir().unwrap();
    corrupt_with_wal(directory.path());
    let dir = directory.path().join(STATE_DIR);
    fs::write(dir.join("honk.db.corrupt"), b"earlier").unwrap();
    assert!(reset_corrupt(directory.path()).unwrap().is_none());
    assert_eq!(fs::read(dir.join("honk.db.corrupt")).unwrap(), b"earlier");
    assert_eq!(
        fs::read(db_path(directory.path())).unwrap(),
        vec![0x5a; 8192]
    );
    assert_eq!(fs::read(dir.join("honk.db-wal")).unwrap(), b"wal");
}

#[test]
fn reset_refuses_while_another_process_holds_the_directory() {
    let directory = tempfile::tempdir().unwrap();
    corrupt_with_wal(directory.path());
    let held = Flock::lock(
        state_directory(directory.path(), false, private).unwrap(),
        FlockArg::LockSharedNonblock,
    )
    .unwrap();
    assert_eq!(
        reset_corrupt(directory.path()).err(),
        Some(StateError::InUse)
    );
    assert_eq!(
        fs::read(db_path(directory.path())).unwrap(),
        vec![0x5a; 8192]
    );
    assert!(
        !directory
            .path()
            .join(STATE_DIR)
            .join("honk.db.corrupt")
            .exists()
    );
    drop(held);
    assert!(reset_corrupt(directory.path()).unwrap().is_some());
}

#[test]
fn admin_reset_refuses_startup_before_the_database_exists() {
    let data = tempfile::tempdir().unwrap();
    let startup = Flock::lock(
        state_directory(data.path(), true, private).unwrap(),
        FlockArg::LockSharedNonblock,
    )
    .unwrap();

    assert!(!db_path(data.path()).exists());
    assert_eq!(reset_admin(data.path()), Err(StateError::InUse));

    drop(startup);
    assert_eq!(reset_admin(data.path()), Ok(false));
}

#[test]
fn cache_connections_sync_fully_without_wal() {
    assert_eq!(synchronous(Class::Cache, true), "NORMAL");
    assert_eq!(synchronous(Class::Cache, false), "FULL");
    assert_eq!(synchronous(Class::Strict, true), "FULL");
}

#[test]
fn tables_of_disabled_owners_are_cleared_and_strict_tables_kept() {
    let directory = tempfile::tempdir().unwrap();
    let state = StateDb::open(directory.path()).unwrap();
    let count = |table: &str| -> i64 {
        state
            .strict()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    let seed = || {
        state
            .strict()
            .execute_batch(
                "INSERT OR REPLACE INTO selector VALUES ('g', 'tcp', '\"m\"');
                 INSERT OR REPLACE INTO delay_sample VALUES ('n', 5, 1);
                 INSERT OR REPLACE INTO dns_answer VALUES ('k', 1, x'00');
                 INSERT OR REPLACE INTO clash_state VALUES ('mode', 'Rule');
                 INSERT OR REPLACE INTO subscription_body VALUES ('s', 1, x'00');
                 INSERT OR REPLACE INTO legacy_import VALUES ('source', 1);",
            )
            .unwrap();
    };
    let tables = [
        "selector",
        "delay_sample",
        "dns_answer",
        "clash_state",
        "subscription_body",
        "legacy_import",
    ];

    seed();
    let owners = ActiveOwners {
        cache: true,
        dns: false,
        clash: true,
        subscriptions: true,
    };
    clear_inactive(&state, owners).unwrap();
    assert_eq!(tables.map(count), [1, 1, 0, 1, 1, 1]);

    seed();
    clear_inactive(
        &state,
        ActiveOwners {
            clash: false,
            ..owners
        },
    )
    .unwrap();
    assert_eq!(tables.map(count), [1, 1, 0, 0, 1, 1]);

    seed();
    clear_inactive(
        &state,
        ActiveOwners {
            cache: false,
            dns: true,
            clash: true,
            subscriptions: true,
        },
    )
    .unwrap();
    assert_eq!(tables.map(count), [0, 0, 0, 0, 1, 1]);

    seed();
    clear_inactive(
        &state,
        ActiveOwners {
            subscriptions: false,
            ..owners
        },
    )
    .unwrap();
    assert_eq!(tables.map(count), [1, 1, 0, 1, 0, 1]);
}

// Builds before the schema was folded into one statement wrote version 1
// without `geodata_settings`; later builds wrote version 1 with it. Version 2
// added no `geodata_status`. All upgrade to the current version and keep their
// rows.
#[test]
fn older_databases_upgrade() {
    for downgrade in [
        "DROP TABLE geodata_status; DROP TABLE geodata_settings; PRAGMA user_version = 1;",
        "DROP TABLE geodata_status; INSERT INTO geodata_settings (id, record) VALUES (1, '{}'); PRAGMA user_version = 1;",
        "DROP TABLE geodata_status; INSERT INTO geodata_settings (id, record) VALUES (1, '{}'); PRAGMA user_version = 2;",
    ] {
        let directory = tempfile::tempdir().unwrap();
        drop(StateDb::open(directory.path()).unwrap());
        let connection = Connection::open(db_path(directory.path())).unwrap();
        connection.execute_batch(downgrade).unwrap();
        drop(connection);
        let state = StateDb::open(directory.path()).unwrap();
        assert_eq!(pragma(&state.strict(), "user_version"), Ok(SCHEMA_VERSION));
        state
            .strict()
            .execute(
                "INSERT OR REPLACE INTO geodata_settings (id, record) VALUES (1, '{\"a\":1}')",
                [],
            )
            .unwrap();
        drop(state);
        let state = StateDb::open(directory.path()).unwrap();
        let record: String = state
            .strict()
            .query_row("SELECT record FROM geodata_settings", [], |row| row.get(0))
            .unwrap();
        assert_eq!(record, "{\"a\":1}");
        let status: i64 = state
            .strict()
            .query_row("SELECT count(*) FROM geodata_status", [], |row| row.get(0))
            .unwrap();
        assert_eq!(status, 0);
    }
}
