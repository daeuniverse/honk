use std::fs;

use super::*;

fn now() -> i64 {
    i64::try_from(now_unix()).unwrap()
}

/// A legacy `cache.db` in WAL mode, left open so its `-wal` exists.
fn seed(path: &Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE kv (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);",
        )
        .unwrap();
    let fresh = serde_json::json!({"delay_ms": 42, "measured_at": now() - 60}).to_string();
    let stale = serde_json::json!({"delay_ms": 7, "measured_at": now() - 25 * 3600}).to_string();
    // `dns:v2:` values are BLOBs, as the old cache wrote them.
    connection
        .execute_batch(
            "INSERT INTO kv (key, value) VALUES ('dns:v2:abcd', x'00'), ('gw:dns:v2:abcd', x'00');",
        )
        .unwrap();
    for (key, value) in [
        ("selector:tcp:proxy", "\"plain-tcp\""),
        ("selector:proxy", "plain-name-only"),
        ("clash_mode", "Direct"),
        ("gw:selector:tcp:proxy", "\"gw-tcp\""),
        ("gw:selector:udp:proxy", "\"gw-udp\""),
        ("gw:selector:proxy", "gw-name-only"),
        ("gw:selector:GLOBAL", "proxy"),
        ("gw:clash_mode", "Global"),
        ("gw:delay:fresh", fresh.as_str()),
        ("gw:delay:stale", stale.as_str()),
        ("gw:dns:example.com:1", "{}"),
        ("gw:fakeip:1.2.3.4", "x"),
    ] {
        connection
            .execute("INSERT INTO kv (key, value) VALUES (?1, ?2)", [key, value])
            .unwrap();
    }
    connection
}

/// The configuration the seeded rows belong to.
fn scope() -> ImportScope {
    ImportScope {
        selector_groups: ["proxy".to_owned()].into(),
        nodes: ["fresh".to_owned(), "stale".to_owned()].into(),
    }
}

fn rows(state: &StateDb, sql: &str) -> Vec<String> {
    let connection = state.strict();
    let mut statement = connection.prepare(sql).unwrap();
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn all_rows(state: &StateDb) -> Vec<String> {
    rows(
        state,
        "SELECT grp || '/' || network || '=' || member FROM selector
         UNION ALL SELECT key || '=' || value FROM clash_state
         UNION ALL SELECT node || '=' || delay_ms FROM delay_sample
         UNION ALL SELECT key FROM dns_answer
         ORDER BY 1",
    )
}

#[test]
fn cache_id_selects_the_imported_prefix_and_keeps_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    let legacy = seed(&path);
    let state = StateDb::open(directory.path()).unwrap();
    let cache = LegacyCache {
        path: path.clone(),
        cache_id: "gw".into(),
    };
    import_cache_db(&state, &cache, &scope());
    assert_eq!(
        all_rows(&state),
        [
            "fresh=42",
            "global=proxy",
            "mode=Global",
            "proxy/tcp=\"gw-tcp\"",
            "proxy/udp=\"gw-udp\""
        ]
    );
    assert!(path.exists(), "another instance may share the file");

    state.strict().execute("DELETE FROM selector", []).unwrap();
    import_cache_db(&state, &cache, &scope());
    assert!(
        rows(&state, "SELECT grp FROM selector").is_empty(),
        "a recorded source is not copied again"
    );
    drop(legacy);
}

#[test]
fn empty_cache_id_imports_plain_keys_and_removes_the_file_and_sidecars_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    let legacy = seed(&path);
    let wal = directory.path().join("cache.db-wal");
    assert!(wal.exists());
    let corrupt = directory.path().join("cache.db.corrupt-1700000000");
    fs::write(&corrupt, b"old").unwrap();
    let state = StateDb::open(directory.path()).unwrap();
    state
        .strict()
        .execute(
            "INSERT INTO clash_state (key, value) VALUES ('mode', 'Rule')",
            [],
        )
        .unwrap();
    import_cache_db(
        &state,
        &LegacyCache {
            path: path.clone(),
            cache_id: String::new(),
        },
        &scope(),
    );
    assert_eq!(
        all_rows(&state),
        ["mode=Rule", "proxy/tcp=\"plain-tcp\""],
        "existing rows win"
    );
    for gone in [&path, &wal, &directory.path().join("cache.db-shm")] {
        assert!(!gone.exists(), "{}", gone.display());
    }
    assert_eq!(
        fs::read(&corrupt).unwrap(),
        b"old",
        "diagnostic copies stay"
    );
    drop(legacy);
}

#[test]
fn a_copied_file_left_behind_is_removed_without_new_rows() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    drop(seed(&path));
    let state = StateDb::open(directory.path()).unwrap();
    let file = LegacyFile::open(&path).unwrap();
    assert!(copy_cache_db(&state, &file, "", &source_key(&file.path, ""), &scope()).unwrap());
    state.strict().execute("DELETE FROM selector", []).unwrap();
    import_cache_db(
        &state,
        &LegacyCache {
            path: path.clone(),
            cache_id: String::new(),
        },
        &scope(),
    );
    assert!(!path.exists());
    assert!(rows(&state, "SELECT grp FROM selector").is_empty());
}

#[test]
fn locate_keeps_the_legacy_resolver() {
    let directory = tempfile::tempdir().unwrap();
    let absolute = directory.path().join("elsewhere.db");
    assert_eq!(
        LegacyCache::locate(absolute.to_str(), Some("gw"), Some(Path::new("/etc/honk"))),
        LegacyCache {
            path: absolute,
            cache_id: "gw".into(),
        }
    );
    let name = format!("cache-{}.db", uuid::Uuid::new_v4());
    fs::write(directory.path().join(&name), b"").unwrap();
    assert_eq!(
        LegacyCache::locate(Some(&name), None, Some(directory.path())).path,
        directory.path().join(&name)
    );
}

fn untouched(state: &StateDb, path: &Path, contents: &[u8]) {
    assert_eq!(fs::read(path).unwrap(), contents);
    assert!(rows(state, "SELECT source FROM legacy_import").is_empty());
    assert!(all_rows(state).is_empty());
}

#[test]
fn a_file_that_is_not_a_cache_db_is_left_and_not_recorded() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let state = StateDb::open(directory.path()).unwrap();
    let legacy = |path: &Path| LegacyCache {
        path: path.to_path_buf(),
        cache_id: String::new(),
    };

    let garbage = directory.path().join("garbage.db");
    fs::write(&garbage, vec![0x5a; 8192]).unwrap();
    fs::set_permissions(&garbage, fs::Permissions::from_mode(0o600)).unwrap();
    import_cache_db(&state, &legacy(&garbage), &scope());
    untouched(&state, &garbage, &[0x5a; 8192]);

    let other = directory.path().join("other.db");
    Connection::open(&other)
        .unwrap()
        .execute_batch("CREATE TABLE unrelated (x)")
        .unwrap();
    let bytes = fs::read(&other).unwrap();
    import_cache_db(&state, &legacy(&other), &scope());
    untouched(&state, &other, &bytes);

    let shared = directory.path().join("shared.db");
    drop(seed(&shared));
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o666)).unwrap();
    let bytes = fs::read(&shared).unwrap();
    import_cache_db(&state, &legacy(&shared), &scope());
    untouched(&state, &shared, &bytes);

    let target = directory.path().join("target.db");
    drop(seed(&target));
    let bytes = fs::read(&target).unwrap();
    let link = directory.path().join("link.db");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    import_cache_db(&state, &legacy(&link), &scope());
    untouched(&state, &target, &bytes);
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn rows_for_groups_and_nodes_outside_the_configuration_are_not_imported() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    let legacy = seed(&path);
    let state = StateDb::open(directory.path()).unwrap();
    import_cache_db(
        &state,
        &LegacyCache {
            path,
            cache_id: "gw".into(),
        },
        &ImportScope::default(),
    );
    assert_eq!(all_rows(&state), ["global=proxy", "mode=Global"]);
    drop(legacy);
}

#[test]
fn a_bare_legacy_name_is_looked_up_in_the_current_directory() {
    assert_eq!(directory_of(Path::new("cache.db")), Path::new("."));
    assert_eq!(directory_of(Path::new("etc/cache.db")), Path::new("etc"));
    assert_eq!(directory_of(Path::new("/srv/cache.db")), Path::new("/srv"));
    // `-c config.dae` has an empty parent, which the old resolver turns into
    // the bare name.
    let located = LegacyCache::locate(None, None, Path::new("config.dae").parent());
    assert!(
        located.path == Path::new("cache.db") || located.path.is_absolute(),
        "{}",
        located.path.display()
    );
}

#[test]
fn an_import_over_the_cache_budget_is_not_committed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    let legacy = Connection::open(&path).unwrap();
    legacy
        .execute_batch("CREATE TABLE kv (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);")
        .unwrap();
    let sample = serde_json::json!({"delay_ms": 5, "measured_at": now()}).to_string();
    let mut scope = ImportScope::default();
    for index in 0..400 {
        let node = format!("{index:0>1000}");
        legacy
            .execute(
                "INSERT INTO kv VALUES (?1, ?2)",
                [format!("delay:{node}"), sample.clone()],
            )
            .unwrap();
        scope.nodes.insert(node);
    }
    drop(legacy);
    // A budget of 32 pages: the 400 samples need far more.
    let state = StateDb::open_for_test(directory.path(), 6144 + 32);
    let cache = LegacyCache {
        path: path.clone(),
        cache_id: String::new(),
    };
    import_cache_db(&state, &cache, &scope);
    assert!(all_rows(&state).is_empty());
    assert!(path.exists(), "the file stays for a later start");
    let used = super::super::used_pages(&state.strict()).unwrap();
    assert!(used <= state.cache_budget_pages(), "{used} pages in use");
}
