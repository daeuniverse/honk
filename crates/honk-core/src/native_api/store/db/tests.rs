use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use honk_config::parser::{SourceLimits, parse_dae_sources};

use super::*;

const MAIN: &str = "global { log_level: info }\nexperimental { native_api { enabled: true } }\n";

struct Fixture {
    _directory: tempfile::TempDir,
    data_dir: PathBuf,
    entry: PathBuf,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let data_dir = directory.path().join("data");
    fs::create_dir(&data_dir).unwrap();
    Fixture {
        entry: directory.path().join("etc/config.dae"),
        data_dir,
        _directory: directory,
    }
}

fn db_path(fixture: &Fixture) -> PathBuf {
    fixture
        .data_dir
        .join(crate::state::STATE_DIR)
        .join(crate::state::DB_FILE)
}

fn sources(entry: &Path, content: &str) -> Vec<SourceSnapshot> {
    parse_dae_sources(
        &[(entry.to_path_buf(), Arc::from(content))],
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap()
    .sources
}

fn initialized(fixture: &Fixture) -> DbStore {
    let store = DbStore::open_in(&fixture.data_dir, &fixture.entry).unwrap();
    let main = sources(&fixture.entry, MAIN);
    let secrets = StoredSecrets {
        native_api: "native-token".into(),
        clash_api: String::new(),
    };
    assert_eq!(
        store.initialize(&main, &ListenerSecrets::empty(), &secrets, "startup"),
        Ok(1)
    );
    store
}

fn write(store: &DbStore, content: &str) -> Pending {
    let pin = store.pin(store.entry()).unwrap();
    let candidate = sources(store.entry(), content);
    store
        .commit(pin, content, &candidate, "control", Box::new(|| Ok(())))
        .unwrap()
}

#[test]
fn an_open_db_keeps_the_entry_of_its_active_revision() {
    let fixture = fixture();
    let store = DbStore::open_in(&fixture.data_dir, &fixture.entry).unwrap();
    assert!(db_path(&fixture).is_file());
    assert_eq!(store.head(), Ok(None));
    drop(store);

    let reopened = initialized(&fixture);
    drop(reopened);
    let store = DbStore::open_in(&fixture.data_dir, Path::new("/elsewhere/other.dae")).unwrap();
    assert_eq!(store.entry(), fixture.entry);
    let loaded = store.load(&HashMap::new(), &mut Vec::new()).unwrap();
    assert_eq!(loaded.config.experimental.native_api.secret, "native-token");
    assert_eq!(loaded.config.global.log_level, "info");
}

#[test]
fn source_labels_resolve_lexically_inside_the_root() {
    let fixture = fixture();
    let store = DbStore::open_in(&fixture.data_dir, &fixture.entry).unwrap();
    let root = fixture.entry.parent().unwrap();
    assert_eq!(
        store.resolve("conf.d/a.dae").unwrap(),
        root.join("conf.d/a.dae")
    );
    assert_eq!(
        store.resolve(root.join("b.dae").to_str().unwrap()).unwrap(),
        root.join("b.dae")
    );
    assert_eq!(
        store.resolve("conf.d/./a.dae").unwrap(),
        root.join("conf.d/a.dae")
    );
    for label in [
        "../escape.dae",
        "/other/c.dae",
        "conf.d/../a.dae",
        "notes.txt",
        "",
    ] {
        assert!(store.resolve(label).is_err(), "{label}");
    }
}

#[test]
fn promote_on_a_moved_head_conflicts() {
    let fixture = fixture();
    let store = initialized(&fixture);
    let first = write(&store, "global { log_level: debug }\n");
    let second = write(&store, "global { log_level: warn }\n");
    assert_eq!(store.promote(first), Ok(2));
    assert_eq!(store.promote(second), Err(WriteError::Conflict));
    assert_eq!(store.head(), Ok(Some(2)));

    let fixture = self::fixture();
    let store = initialized(&fixture);
    let pin = store.pin(store.entry()).unwrap();
    assert_eq!(store.promote(write(&store, "global {}\n")), Ok(2));
    let content = "global { log_level: error }\n";
    let candidate = sources(store.entry(), content);
    assert_eq!(
        store
            .commit(pin, content, &candidate, "control", Box::new(|| Ok(())))
            .err(),
        Some(WriteError::Conflict)
    );
}

#[test]
fn candidates_with_listener_secrets_are_not_recorded() {
    let fixture = fixture();
    let store = initialized(&fixture);
    let refused = |content: &str| {
        let pin = store.pin(store.entry()).unwrap();
        let candidate = sources(store.entry(), content);
        store
            .commit(pin, content, &candidate, "control", Box::new(|| Ok(())))
            .err()
    };
    assert_eq!(
        refused("experimental { native_api { secret: 'leaked' } }\n"),
        Some(WriteError::SecretSource)
    );
    assert_eq!(refused("# native-token\n"), Some(WriteError::SecretContent));
}

#[test]
fn retention_keeps_fifty_revisions_and_the_active_one() {
    let fixture = fixture();
    let store = initialized(&fixture);
    for index in 0..55 {
        let number = store
            .promote(write(
                &store,
                &format!("global {{ tproxy_port: {} }}\n", 20000 + index),
            ))
            .unwrap();
        assert_eq!(number, index + 2);
    }
    let connection = store.state.strict();
    let (count, oldest): (i64, i64) = connection
        .query_row("SELECT count(*), min(number) FROM revision", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!((count, oldest), (MAX_REVISIONS as i64, 7));
    let parent: Option<i64> = connection
        .query_row("SELECT parent FROM revision WHERE number = 7", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(parent, None);
    assert_eq!(head(&connection), Ok(Some(56)));
    drop(connection);
    let loaded = store.load(&HashMap::new(), &mut Vec::new()).unwrap();
    assert_eq!(loaded.config.global.tproxy_port, 20054);
}

#[test]
fn cli_export_restores_secrets_into_a_new_private_file() {
    let fixture = fixture();
    let store = initialized(&fixture);
    let out = fixture.data_dir.join("export.dae");
    export_to(&fixture.data_dir, &out, true).unwrap();
    assert_eq!(
        fs::symlink_metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = fs::read_to_string(&out).unwrap();
    let exported = honk_config::parser::parse_dae_config(&text).unwrap();
    exported.validate().unwrap();
    assert_eq!(exported.experimental.native_api.secret, "native-token");
    assert_eq!(
        exported,
        store.load(&HashMap::new(), &mut Vec::new()).unwrap().config
    );

    let bare = fixture.data_dir.join("bare.dae");
    export_to(&fixture.data_dir, &bare, false).unwrap();
    let text = fs::read_to_string(&bare).unwrap();
    assert!(text.starts_with("# listener secrets omitted\n"));
    assert!(!text.contains("native-token"));

    fs::write(&out, "kept").unwrap();
    assert!(export_to(&fixture.data_dir, &out, true).is_err());
    assert_eq!(fs::read_to_string(&out).unwrap(), "kept");
    assert!(fs::read_dir(&fixture.data_dir).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
    assert_eq!(store.head(), Ok(Some(1)));
}

#[test]
fn head_cache_and_existence_follow_promote() {
    let fixture = fixture();
    let store = initialized(&fixture);
    assert_eq!(store.cached_head(), Some((1, None)));
    let pending = write(&store, "global { log_level: debug }\n");
    assert_eq!(store.promote(pending), Ok(2));
    assert_eq!(store.cached_head(), Some((2, Some(1))));
    assert_eq!(store.revision_exists(1), Ok(true));
    assert_eq!(store.revision_exists(9), Ok(false));
}

#[test]
fn retention_counts_the_stored_json() {
    let fixture = fixture();
    let store = initialized(&fixture);
    // 4.5 MiB of source, 9 MiB once JSON escapes every quote.
    let quoted = format!("global {{}}\n# {}\n", "\"".repeat(4608 * 1024));
    assert_eq!(store.promote(write(&store, &quoted)), Ok(2));
    for (number, lose_reply) in [(3, false), (4, true)] {
        let again = format!("{quoted}# revision {number}\n");
        store.lose_commit_reply.store(lose_reply, Ordering::Release);
        assert_eq!(store.promote(write(&store, &again)), Ok(number));
        assert!(!store.blocked());
        assert_eq!(store.cached_head(), Some((number, None)));
        let (active, revisions) = store.revisions().unwrap();
        assert_eq!(active, Some(number));
        assert_eq!(
            revisions
                .iter()
                .map(|row| (row.number, row.parent))
                .collect::<Vec<_>>(),
            [(number, None)]
        );
    }

    // 3 MiB of control characters stores as 18 MiB of `\u0001` escapes.
    let content = format!("global {{}}\n# {}\n", "\u{1}".repeat(3 * 1024 * 1024));
    let pin = store.pin(store.entry()).unwrap();
    let candidate = sources(store.entry(), &content);
    assert_eq!(
        store
            .commit(pin, &content, &candidate, "control", Box::new(|| Ok(())))
            .err(),
        Some(WriteError::TooLarge)
    );
}

#[test]
fn export_reads_the_db_with_and_without_a_daemon_connection() {
    let fixture = fixture();
    let store = initialized(&fixture);
    assert_eq!(store.promote(write(&store, MAIN)), Ok(2));
    let open = export(&fixture.data_dir, false).unwrap();
    drop(store);
    assert_eq!(export(&fixture.data_dir, false).unwrap(), open);
    assert!(open.contains("log_level: info"));
}

/// A copy of `fixture`'s db as a crash leaves it in the middle of a
/// transaction under a rollback journal: pages written, journal hot.
fn hot_journal_copy(fixture: &Fixture) -> tempfile::TempDir {
    let path = db_path(fixture);
    Connection::open(&path)
        .unwrap()
        .execute_batch("PRAGMA journal_mode = DELETE")
        .unwrap();
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch(
            "PRAGMA cache_size = 10;
             BEGIN IMMEDIATE;
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5000)
             INSERT INTO legacy_import (source, done_at) SELECT 'row' || i, i FROM n;",
        )
        .unwrap();
    let copy = tempfile::tempdir().unwrap();
    let state = copy.path().join(crate::state::STATE_DIR);
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    for name in [crate::state::DB_FILE, "honk.db-journal"] {
        let source = path.with_file_name(name);
        fs::copy(&source, state.join(name)).unwrap();
        fs::set_permissions(state.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    drop(writer);
    assert!(fs::metadata(state.join("honk.db-journal")).unwrap().len() > 0);
    copy
}

#[test]
fn a_hot_rollback_journal_is_rolled_back_by_open_and_by_export() {
    let fixture = fixture();
    drop(initialized(&fixture));
    let exported = hot_journal_copy(&fixture);
    let text = export(exported.path(), false).unwrap();
    assert!(text.contains("log_level: info"));

    let opened = hot_journal_copy(&fixture);
    let state = StateDb::open(opened.path()).unwrap();
    let rows: i64 = state
        .strict()
        .query_row("SELECT count(*) FROM legacy_import", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0, "the interrupted transaction is rolled back");
}

#[test]
fn export_closing_last_leaves_the_wal_in_place() {
    let fixture = fixture();
    let store = initialized(&fixture);
    assert_eq!(store.promote(write(&store, MAIN)), Ok(2));
    // A copy taken while the store is open is what a crashed daemon leaves.
    let copy = tempfile::tempdir().unwrap();
    let state = copy.path().join(crate::state::STATE_DIR);
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    for name in [crate::state::DB_FILE, "honk.db-wal"] {
        fs::copy(db_path(&fixture).with_file_name(name), state.join(name)).unwrap();
        fs::set_permissions(state.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    drop(store);
    let wal = fs::read(state.join("honk.db-wal")).unwrap();
    assert!(!wal.is_empty());
    assert!(
        export(copy.path(), false)
            .unwrap()
            .contains("log_level: info")
    );
    assert_eq!(fs::read(state.join("honk.db-wal")).unwrap(), wal);
}
