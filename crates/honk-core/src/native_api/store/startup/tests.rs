use std::fs;
use std::path::PathBuf;

use super::*;

fn tree(data_dir: &Path) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let packet = if crate::PACKET_ONLY {
        "datapath {\n backend: tun\n direct: endpoint\n tun {\n name: honk0\n address4: 198.18.0.1/32\n table: 202\n rule_priority: 10000\n capture { 0.0.0.0/0 }\n }\n}\n"
    } else {
        ""
    };
    fs::write(
        root.join("config.dae"),
        format!(
            "include {{ 'auth.dae' }}\nglobal {{ data_dir: '{}'\n nfqueue_enable: false }}\nrouting {{ fallback: direct }}\n{packet}",
            data_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        root.join("auth.dae"),
        "experimental { native_api { enabled: true\n secret: 'startup-token'\n config_write: true } }\n",
    )
    .unwrap();
    (directory, root.join("config.dae"))
}

fn assert_removed_warnings(diagnostics: &[DetailedDiagnostic]) {
    assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
    for (notice, key) in diagnostics
        .iter()
        .zip(["probe_allowed_cidrs", "probe_allowed_ports"])
    {
        assert_eq!(
            notice.setting.to_string(),
            format!("experimental.native_api.{key}")
        );
        assert_eq!(notice.code, "legacy-config-warning");
        assert_eq!(notice.severity, honk_config::diagnostic::Severity::Warning);
    }
}

#[test]
fn import_strips_secrets_and_a_later_start_reads_only_the_head() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (directory, entry) = tree(&data_dir);
    let removed = "experimental { native_api {\n probe_allowed_cidrs: PRIVATE\n probe_allowed_ports: 0, 65536, invalid\n } }\n";
    let mut content = fs::read_to_string(&entry).unwrap();
    content.push_str(removed);
    fs::write(&entry, content).unwrap();
    let mut diagnostics = Vec::new();
    let mut startup = DatabaseStartup::open(&entry, &data_dir, &mut diagnostics).unwrap();
    assert_removed_warnings(&diagnostics);
    assert!(startup.sources.sources[0].content.ends_with(removed));
    assert!(
        startup
            .sources
            .sources
            .iter()
            .all(|source| !source.contains_api_secret && !source.content.contains("startup-token"))
    );
    assert_eq!(
        startup.config.experimental.native_api.secret,
        "startup-token"
    );
    startup.record().unwrap();
    let imported = startup.config.clone();
    drop(startup);
    drop(directory);

    diagnostics.clear();
    let reopened = DatabaseStartup::open(&entry, &data_dir, &mut diagnostics).unwrap();
    assert_removed_warnings(&diagnostics);
    assert!(reopened.sources.sources[0].content.ends_with(removed));
    assert_eq!(reopened.config, imported);
    assert_eq!(reopened.store.head(), Ok(Some(1)));
}

#[test]
fn import_preserves_declared_nodes_groups_and_subscriptions() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (directory, entry) = tree(&data_dir);
    let mut content = fs::read_to_string(&entry).unwrap();
    content.push_str(
        "\nnode { edge: 'socks5://127.0.0.1:1080' }\n\
         subscription { feed: 'http://127.0.0.1:9/feed' }\n\
         group { proxy { filter: name(edge)\n policy: select } }\n",
    );
    fs::write(&entry, &content).unwrap();
    let mut startup = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new()).unwrap();
    startup.record().unwrap();
    drop(startup);
    drop(directory);

    let reopened = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new()).unwrap();
    let edge = reopened
        .config
        .nodes
        .iter()
        .find(|node| node.name == "edge")
        .unwrap();
    assert_eq!(edge.address, "127.0.0.1:1080");
    assert_eq!(reopened.config.groups[0].name, "proxy");
    assert_eq!(reopened.config.groups[0].nodes, vec![edge.id]);
    assert_eq!(reopened.config.subscriptions[0].name, "feed");
    assert_eq!(
        reopened.config.subscriptions[0].url,
        "http://127.0.0.1:9/feed"
    );
    assert_eq!(
        reopened.config.experimental.native_api.secret,
        "startup-token"
    );
    assert!(
        reopened
            .sources
            .sources
            .iter()
            .all(|source| !source.content.contains("startup-token"))
    );
}

#[test]
fn stripped_roundtrip_keeps_declared_values_and_derived_node_identity() {
    let text = "node { edge: 'socks5://127.0.0.1:1080' }\n\
                subscription { feed: 'http://127.0.0.1:9/feed' }\n\
                group { proxy { filter: name(edge)\n policy: select } }\n";
    let original = honk_config::parser::parse_dae_config(text).unwrap();
    let mut reparsed = honk_config::parser::parse_dae_config(text).unwrap();
    assert!(stripped_config_matches(&original, &mut reparsed));

    let mut changed = reparsed.clone();
    changed.nodes[0].address = "127.0.0.1:1081".into();
    assert!(!stripped_config_matches(&original, &mut changed));
    let mut changed = reparsed.clone();
    changed.nodes[0].id = uuid::Uuid::new_v4();
    assert!(!stripped_config_matches(&original, &mut changed));
    let mut changed = reparsed.clone();
    changed.groups[0].name = "different".into();
    assert!(!stripped_config_matches(&original, &mut changed));
    reparsed.subscriptions[0].url = "http://127.0.0.1:9/changed".into();
    assert!(!stripped_config_matches(&original, &mut reparsed));
}

#[test]
fn data_dir_mismatch_refuses_startup() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (_directory, entry) = tree(&data_dir.join("elsewhere"));
    let error = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new())
        .err()
        .expect("mismatched data_dir must refuse startup");
    assert!(error.to_string().contains("--data-dir"), "{error}");
    let store = DbStore::open_in(&data_dir, &entry).unwrap();
    assert_eq!(store.head(), Ok(None));
}

#[test]
fn secret_copy_in_a_comment_refuses_import() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (_directory, entry) = tree(&data_dir);
    let mut main = fs::read_to_string(&entry).unwrap();
    main.push_str("# old startup-token copied here\n");
    fs::write(&entry, main).unwrap();
    let error = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new())
        .err()
        .expect("a secret copy must refuse the import");
    assert!(error.to_string().contains("copies"), "{error}");
}

#[test]
fn head_moved_before_the_instance_lock_refuses_startup() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (_directory, entry) = tree(&data_dir);
    DatabaseStartup::open(&entry, &data_dir, &mut Vec::new())
        .unwrap()
        .record()
        .unwrap();
    let mut waiting = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new()).unwrap();
    let running = DbStore::open_in(&data_dir, &entry).unwrap();
    let pin = running.pin(running.entry()).unwrap();
    let mut candidate = waiting.sources.sources.clone();
    let content = format!("{}# edited\n", candidate[0].content);
    candidate[0].content = Arc::from(content.as_str());
    let pending = running
        .commit(pin, &content, &candidate, "control", Box::new(|| Ok(())))
        .unwrap();
    assert_eq!(running.promote(pending), Ok(2));
    let error = waiting.record().expect_err("a moved head must refuse");
    assert!(error.to_string().contains("moved"), "{error}");
}

const CONTROLLER: &str = "clash_api { external_controller: '127.0.0.1:9090' }\n native_api {";

#[test]
fn clash_controller_refuses_the_import() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (directory, entry) = tree(&data_dir);
    let auth = directory.path().canonicalize().unwrap().join("auth.dae");
    let content = fs::read_to_string(&auth).unwrap();
    fs::write(&auth, content.replace("native_api {", CONTROLLER)).unwrap();
    let error = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new())
        .err()
        .expect("a Clash controller must refuse the import");
    assert!(
        error.to_string().contains("without the Clash API"),
        "{error}"
    );
    let store = DbStore::open_in(&data_dir, &entry).unwrap();
    assert_eq!(store.head(), Ok(None));
}

#[test]
fn clash_controller_in_the_head_refuses_startup() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (_directory, entry) = tree(&data_dir);
    let startup = {
        let mut startup = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new()).unwrap();
        startup.record().unwrap();
        startup
    };
    let mut candidate = startup.sources.sources.clone();
    drop(startup);
    let store = DbStore::open_in(&data_dir, &entry).unwrap();
    let auth = candidate
        .iter_mut()
        .find(|source| source.path.ends_with("auth.dae"))
        .unwrap();
    let pin = store.pin(&auth.path).unwrap();
    let content = auth.content.replace("native_api {", CONTROLLER);
    auth.content = Arc::from(content.as_str());
    let pending = store
        .commit(pin, &content, &candidate, "control", Box::new(|| Ok(())))
        .unwrap();
    assert_eq!(store.promote(pending), Ok(2));
    drop(store);
    let error = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new())
        .err()
        .expect("a head with a Clash controller must refuse startup");
    assert!(
        error.to_string().contains("without the Clash API"),
        "{error}"
    );
}

struct Refusal {
    name: &'static str,
    /// Breaks one precondition of the tree that `tree` writes.
    edit: fn(entry: &Path, auth: &Path),
    needle: &'static str,
}

fn replace_in(path: &Path, from: &str, to: &str) {
    let content = fs::read_to_string(path).unwrap();
    assert!(content.contains(from), "{from} not in {content}");
    fs::write(path, content.replace(from, to)).unwrap();
}

const REFUSALS: &[Refusal] = &[
    Refusal {
        name: "native api disabled",
        edit: |_, auth| replace_in(auth, "enabled: true", "enabled: false"),
        needle: "--store db needs experimental.native_api",
    },
    Refusal {
        name: "config_write off",
        edit: |_, auth| replace_in(auth, "config_write: true", "config_write: false"),
        needle: "--store db needs experimental.native_api",
    },
    Refusal {
        name: "clash controller",
        edit: |_, auth| replace_in(auth, "native_api {", CONTROLLER),
        needle: "without the Clash API",
    },
    Refusal {
        name: "data dir mismatch",
        edit: |entry, _| replace_in(entry, "data_dir: '", "data_dir: '/elsewhere"),
        needle: "differs from --data-dir",
    },
    Refusal {
        name: "secret copy",
        edit: |entry, _| {
            let mut main = fs::read_to_string(entry).unwrap();
            main.push_str("# old startup-token copied here\n");
            fs::write(entry, main).unwrap();
        },
        needle: "copies",
    },
    Refusal {
        name: "missing entry",
        edit: |entry, _| fs::remove_file(entry).unwrap(),
        needle: "cannot be imported",
    },
];

fn refused(entry: &Path, data_dir: &Path) -> String {
    DatabaseStartup::open(entry, data_dir, &mut Vec::new())
        .err()
        .expect("the start must be refused")
        .to_string()
}

#[test]
fn a_refused_import_leaves_nothing_behind() {
    for case in REFUSALS {
        for data_dir_exists in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let data_dir = root.path().canonicalize().unwrap().join("data");
            if data_dir_exists {
                fs::create_dir(&data_dir).unwrap();
            }
            let (directory, entry) = tree(&data_dir);
            (case.edit)(&entry, &directory.path().join("auth.dae"));
            let error = refused(&entry, &data_dir);
            assert!(
                error.contains(case.needle),
                "{} (data dir exists: {data_dir_exists}): {error}",
                case.name
            );
            assert_eq!(data_dir.exists(), data_dir_exists, "{}", case.name);
            assert!(!data_dir.join("state").exists(), "{}", case.name);
        }
    }
}

#[test]
fn a_refused_start_on_an_existing_db_keeps_it() {
    for case in REFUSALS.iter().filter(|case| case.name != "missing entry") {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().canonicalize().unwrap();
        let (directory, entry) = tree(&data_dir);
        // An empty db left by an earlier start; a db with a head is covered above.
        drop(DbStore::open_in(&data_dir, &entry).unwrap());
        (case.edit)(&entry, &directory.path().join("auth.dae"));
        assert!(
            refused(&entry, &data_dir).contains(case.needle),
            "{}",
            case.name
        );
        assert_eq!(
            DbStore::open_in(&data_dir, &entry).unwrap().head(),
            Ok(None)
        );
    }
}

#[test]
fn a_good_config_creates_the_data_dir_and_records_revision_one() {
    let root = tempfile::tempdir().unwrap();
    let data_dir = root
        .path()
        .canonicalize()
        .unwrap()
        .join("nested")
        .join("data");
    let (_directory, entry) = tree(&data_dir);
    let mut startup = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new()).unwrap();
    assert!(data_dir.join("state").join("honk.db").exists());
    startup.record().unwrap();
    assert_eq!(startup.store.head(), Ok(Some(1)));
}

#[test]
fn the_first_failing_precondition_is_the_one_reported() {
    // Native API, Clash controller and data dir all wrong, then the first one fixed in turn.
    let steps = [
        "--store db needs experimental.native_api",
        "without the Clash API",
        "differs from --data-dir",
    ];
    for existing_empty_db in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().canonicalize().unwrap().join("data");
        let (directory, entry) = tree(&root.path().join("elsewhere"));
        let auth = directory.path().join("auth.dae");
        replace_in(&auth, "native_api {", CONTROLLER);
        replace_in(&auth, "enabled: true", "enabled: false");
        if existing_empty_db {
            fs::create_dir(&data_dir).unwrap();
            drop(DbStore::open_in(&data_dir, &entry).unwrap());
        }
        for needle in steps {
            let error = refused(&entry, &data_dir);
            assert!(error.contains(needle), "{needle}: {error}");
            match needle {
                "--store db needs experimental.native_api" => {
                    replace_in(&auth, "enabled: false", "enabled: true")
                }
                "without the Clash API" => replace_in(
                    &auth,
                    "external_controller: '127.0.0.1:9090'",
                    "external_controller: ''",
                ),
                _ => {}
            }
        }
    }
}

#[cfg(all(feature = "packet-ebpf", not(feature = "legacy-tc")))]
#[tokio::test]
async fn packet_only_rejects_active_db_tc_even_if_file_selects_tun() {
    use clap::Parser as _;
    let root = tempfile::tempdir().unwrap();
    let data = root.path().canonicalize().unwrap().join("data");
    let (_src, entry) = tree(&data);
    let mut startup = DatabaseStartup::open(&entry, &data, &mut Vec::new()).unwrap();
    startup.record().unwrap();
    let mut candidate = startup.sources.sources.clone();
    drop(startup);
    let store = DbStore::open_in(&data, &entry).unwrap();
    let pin = store.pin(&entry).unwrap();
    let root_source = candidate.iter_mut().find(|s| s.path == entry).unwrap();
    let (prefix, _) = root_source.content.split_once("datapath {").unwrap();
    let content = format!("{prefix}datapath {{ backend: tc }}\n");
    root_source.content = Arc::from(content.as_str());
    let pending = store
        .commit(pin, &content, &candidate, "test", Box::new(|| Ok(())))
        .unwrap();
    let head = store.promote(pending).unwrap();
    drop(store);
    let lock = root.path().join("instance.lock");
    crate::TEST_INSTANCE_LOCK.with(|slot| slot.replace(Some(lock.clone())));
    let cli = crate::Cli::try_parse_from([
        "honk-core",
        "--store",
        "db",
        "--data-dir",
        data.to_str().unwrap(),
        "-c",
        entry.to_str().unwrap(),
        "--mock-ebpf",
    ])
    .unwrap();
    let error = crate::run(cli).await.unwrap_err();
    crate::TEST_INSTANCE_LOCK.with(|slot| slot.replace(None));
    assert!(
        format!("{error:#}").contains(crate::TC_BUILD_ERROR),
        "{error:#}"
    );
    assert!(!lock.exists());
    assert_eq!(
        DbStore::open_in(&data, &entry).unwrap().head(),
        Ok(Some(head))
    );
}

#[cfg(all(feature = "packet-ebpf", not(feature = "legacy-tc")))]
#[tokio::test]
async fn packet_only_contended_db_import_creates_no_state() {
    use clap::Parser as _;
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("new-data");
    let (_source, entry) = tree(&data);
    let path = temp.path().join("instance.lock");
    let _held = crate::acquire_instance_lock(&path, std::time::Duration::ZERO).unwrap();
    crate::TEST_INSTANCE_LOCK.with(|slot| slot.replace(Some(path)));
    let cli = crate::Cli::try_parse_from([
        "honk-core",
        "--store",
        "db",
        "--data-dir",
        data.to_str().unwrap(),
        "-c",
        entry.to_str().unwrap(),
    ])
    .unwrap();
    let error = crate::run(cli).await.unwrap_err();
    crate::TEST_INSTANCE_LOCK.with(|slot| slot.replace(None));
    assert!(error.to_string().contains("refusing to start"), "{error:#}");
    assert!(
        !data.exists(),
        "a rejected successor created a state directory"
    );
}
