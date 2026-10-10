//! POST /config/sources: a new file an include pattern loads.

use super::*;

const SOURCES: &str = "/api/v1/config/sources";
const NEW: &str = "config.d/proxies.dae";
const CONTENT: &str = "# Added through the API.\n";

/// Adds `include { 'config.d/*.dae' }` and the directory it names, in either tree.
fn with_include(root: &Path, originals: &mut HashMap<&'static str, String>) {
    for tree in ["", "etc"] {
        std::fs::create_dir_all(root.join(tree).join("config.d")).unwrap();
    }
    let main = originals.get_mut("main.dae").unwrap();
    *main = main.replace("'locked.dae'\n", "'locked.dae'\n 'config.d/*.dae'\n");
}

impl Fixture {
    fn create(&self, path: &str, content: &str) -> reqwest::RequestBuilder {
        self.request(Method::POST, SOURCES)
            .json(&json!({"path":path,"content":content}))
    }
}

fn listed(config: &Value, path: &str) -> bool {
    config["sources"]
        .as_array()
        .unwrap()
        .iter()
        .any(|source| source["path"] == path)
}

#[tokio::test]
async fn created_source_is_loaded_listed_and_never_overwritten() {
    let fixture = Fixture::new_custom(Access::Admin, false, with_include).await;
    let capabilities = fixture.get("/api/v1/capabilities").await;
    assert_eq!(capabilities["resources"]["config"]["create"], true);
    let operation = accepted(
        fixture
            .create(NEW, CONTENT)
            .header("idempotency-key", "create")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(operation["kind"], "reload");
    assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
    let replay = fixture
        .create(NEW, CONTENT)
        .header("idempotency-key", "create")
        .send();
    let replay = accepted(replay.await.unwrap()).await;
    assert_eq!(replay["operation_id"], operation["operation_id"]);
    let path = fixture.path(NEW);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), CONTENT);
    assert_eq!(
        std::fs::metadata(&path).unwrap().mode() & 0o7777,
        0o640,
        "the entry's mode"
    );
    let config = fixture.get(CONFIG).await;
    assert!(listed(&config, NEW));
    assert_eq!(source(&config, CONTENT)["path"], NEW);

    let before = disk(fixture.directory.path());
    let response = fixture.create(NEW, "# Other.\n").send().await.unwrap();
    error(response, StatusCode::CONFLICT, "state_conflict").await;
    assert_eq!(disk(fixture.directory.path()), before);
    fixture.shutdown().await;
}

#[tokio::test]
async fn refused_creations_write_nothing() {
    let outside = tempfile::tempdir().unwrap();
    let escape = outside.path().to_owned();
    let fixture = Fixture::new_custom(Access::Admin, false, |root, originals| {
        with_include(root, originals);
        std::os::unix::fs::symlink(&escape, root.join("config.d/out")).unwrap();
    })
    .await;
    let before = disk(fixture.directory.path());
    for path in [
        "../x.dae",
        "config.d/../x.dae",
        "/etc/x.dae",
        "config.d//x.dae",
        "./config.d/x.dae",
        "config.d/x.txt",
        ".dae",
        "config.d/x\u{1}.dae",
        "config.d/out/x.dae",
    ] {
        let response = fixture.create(path, CONTENT).send().await.unwrap();
        error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
    }
    let main = source(&fixture.get(CONFIG).await, &fixture.originals["main.dae"])["id"].clone();

    let response = fixture.create("extra.dae", CONTENT).send().await.unwrap();
    let body = error(
        response,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    let rows = &body["error"]["details"]["diagnostics"];
    assert_eq!(rows[0]["code"], "source-not-included");
    assert_eq!(rows[0]["source_id"], main);
    assert!(rows[0]["line"].is_null());

    let response = fixture.create(NEW, "routing {\n").send().await.unwrap();
    let body = error(
        response,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    let rows = &body["error"]["details"]["diagnostics"];
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .all(|row| row["source_id"] != main)
    );

    let response = fixture
        .create(NEW, &format!("# {SECRET}\n"))
        .send()
        .await
        .unwrap();
    error(response, StatusCode::FORBIDDEN, "permission_denied").await;
    let response = fixture
        .create(NEW, "experimental { native_api { enabled: false } }\n")
        .send()
        .await
        .unwrap();
    error(response, StatusCode::FORBIDDEN, "permission_denied").await;

    assert_eq!(disk(fixture.directory.path()), before);
    assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn directory_swapped_before_the_rename_writes_nothing() {
    let fixture = Fixture::new_custom(Access::Admin, false, with_include).await;
    let (entered, release) = fixture.pause_before_replace();
    let request = fixture.create(NEW, CONTENT).send();
    let swap = async {
        entered.await.unwrap();
        let directory = fixture.path("config.d");
        let moved = fixture.path("moved.d");
        std::fs::rename(&directory, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &directory).unwrap();
        release.send(()).unwrap();
    };
    let (response, ()) = tokio::join!(request, swap);
    error(response.unwrap(), StatusCode::CONFLICT, "state_conflict").await;
    assert!(
        std::fs::read_dir(fixture.path("moved.d"))
            .unwrap()
            .next()
            .is_none()
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn failed_activation_keeps_the_created_file() {
    let fixture = Fixture::new_custom(Access::Admin, false, with_include).await;
    let before = fixture.get(CONFIG).await;
    fixture
        .reject_reloads
        .store(ReloadBehavior::Reject as u8, Ordering::SeqCst);
    let operation = accepted(fixture.create(NEW, CONTENT).send().await.unwrap()).await;
    let failed = fixture.terminal(&operation).await;
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["error"]["code"], "reload_rejected");
    assert_eq!(failed["error"]["details"]["written"], true);
    assert_eq!(failed["error"]["details"]["committed"], false);
    assert_eq!(std::fs::read_to_string(fixture.path(NEW)).unwrap(), CONTENT);
    assert_eq!(fixture.get(CONFIG).await, before);

    // A degraded commit is active; the failure says so.
    fixture
        .reject_reloads
        .store(ReloadBehavior::Degraded as u8, Ordering::SeqCst);
    let other = "config.d/other.dae";
    let operation = accepted(fixture.create(other, CONTENT).send().await.unwrap()).await;
    let failed = fixture.terminal(&operation).await;
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["error"]["details"]["written"], true);
    assert_eq!(failed["error"]["details"]["committed"], true);
    assert!(failed["error"]["details"]["active_generation_id"].is_string());
    assert!(fixture.path(other).exists());
    fixture.shutdown().await;
}

#[tokio::test]
async fn creation_is_allowed_when_the_main_source_holds_the_api_secret() {
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        with_include(root, files);
        let auth = files.remove("auth.dae").unwrap();
        let main = files.get_mut("main.dae").unwrap();
        *main = main.replace(" 'auth.dae'\n", "");
        main.push_str(&auth);
    })
    .await;
    let capabilities = fixture.get("/api/v1/capabilities").await;
    assert_eq!(capabilities["resources"]["config"]["create"], true);
    let operation = accepted(fixture.create(NEW, CONTENT).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
    assert!(listed(&fixture.get(CONFIG).await, NEW));
    fixture.shutdown().await;
}

#[tokio::test]
async fn database_store_records_the_new_source_as_a_revision() {
    let fixture = Fixture::new_db_custom(Access::Admin, with_include).await;
    let operation = accepted(fixture.create(NEW, CONTENT).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
    assert!(listed(&fixture.get(CONFIG).await, NEW));
    let list = fixture.get("/api/v1/x-honk/config/revisions").await;
    assert_eq!(list["active"], 2);
    assert_eq!(list["revisions"][0]["revision"], 2);
    assert!(
        list["revisions"][0]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["path"] == NEW)
    );
    assert!(!fixture.path("etc").join(NEW).exists());

    let response = fixture.create(NEW, CONTENT).send().await.unwrap();
    error(response, StatusCode::CONFLICT, "state_conflict").await;
    fixture.shutdown().await;
}
