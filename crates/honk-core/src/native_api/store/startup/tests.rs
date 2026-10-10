use std::fs;
use std::path::PathBuf;

use super::*;

fn tree(data_dir: &Path) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    fs::write(
        root.join("config.dae"),
        format!(
            "include {{ 'auth.dae' }}\nglobal {{ data_dir: '{}' }}\nrouting {{ fallback: direct }}\n",
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
