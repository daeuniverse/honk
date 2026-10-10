//! Source writes refuse the listener-secret values the listing masks, and no others.

use super::*;

const GROUP: &str = "group {\n G {\n  policy: selector\n  final: direct\n }\n}\n";
const CLASH: &str = "clash-listener-token";

/// Declares `secret` as the native API secret and adds a writable group and a created-source include.
fn with_secret(secret: &'static str) -> impl FnOnce(&Path, &mut HashMap<&'static str, String>) {
    move |root, files| {
        std::fs::create_dir_all(root.join("config.d")).unwrap();
        let auth = files.get_mut("auth.dae").unwrap();
        *auth = auth.replace(SECRET, secret);
        let main = files.get_mut("main.dae").unwrap();
        *main = main.replace("'locked.dae'\n", "'locked.dae'\n 'config.d/*.dae'\n");
        files.insert("editable.dae", GROUP.into());
    }
}

async fn fixture_with_secret(secret: &'static str) -> Fixture {
    let mut fixture = Fixture::new_custom(Access::Admin, false, with_secret(secret)).await;
    fixture.bearer = secret;
    fixture
}

fn create(fixture: &Fixture, path: &str, content: &str) -> reqwest::RequestBuilder {
    fixture
        .request(Method::POST, "/api/v1/config/sources")
        .json(&json!({"path":path,"content":content}))
}

async fn patch_group(fixture: &Fixture) -> reqwest::RequestBuilder {
    let group = &fixture.get("/api/v1/groups").await[0];
    let path = format!("/api/v1/groups/{}", group["id"].as_str().unwrap());
    let revision = fixture.get(&path).await["config_revision"]
        .as_str()
        .unwrap()
        .to_owned();
    fixture
        .request(Method::PATCH, &format!("{path}/config"))
        .header("if-match", format!("\"{revision}\""))
        .header("content-type", "application/json-patch+json")
        .body(
            json!([{"op":"replace","path":"/config/interrupt_connections","value":true}])
                .to_string(),
        )
}

async fn succeeds(fixture: &Fixture, request: reqwest::RequestBuilder) {
    let operation = accepted(request.send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
}

async fn refused(fixture: &Fixture, request: reqwest::RequestBuilder) {
    let before = disk(fixture.directory.path());
    error(
        request.send().await.unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), before);
}

/// Values shorter than eight bytes are neither masked nor enforced: the listing offers the
/// sources that hold them, and group PATCH, PUT and create write them.
#[tokio::test]
async fn short_listener_secret_is_not_refused_in_written_content() {
    // A substring of `policy: selector`.
    const SHORT: &str = "select";
    let fixture = fixture_with_secret(SHORT).await;
    let config = fixture.get(CONFIG).await;
    assert_eq!(source(&config, GROUP)["writable"], true);
    succeeds(&fixture, patch_group(&fixture).await).await;
    assert_ne!(
        std::fs::read_to_string(fixture.path("editable.dae")).unwrap(),
        GROUP
    );

    let config = fixture.get(CONFIG).await;
    let locked = source(&config, &fixture.originals["locked.dae"]);
    assert_eq!(locked["writable"], true);
    let copied = format!("# {SHORT} copied here\n");
    succeeds(&fixture, fixture.replace(locked, &copied)).await;
    assert_eq!(
        std::fs::read_to_string(fixture.path("locked.dae")).unwrap(),
        copied
    );
    let config = fixture.get(CONFIG).await;
    assert_eq!(source(&config, &copied)["content"], copied);

    succeeds(&fixture, create(&fixture, "config.d/copy.dae", &copied)).await;
    assert_eq!(
        std::fs::read_to_string(fixture.path("config.d/copy.dae")).unwrap(),
        copied
    );

    // The source declaring it still carries a credential.
    let config = fixture.get(CONFIG).await;
    let auth = source(&config, &fixture.originals["auth.dae"]);
    assert_eq!(auth["writable"], false);
    refused(
        &fixture,
        fixture.replace(auth, &fixture.originals["auth.dae"]),
    )
    .await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn eight_byte_listener_secret_is_refused_in_written_content() {
    const EIGHT: &str = "selector";
    let fixture = fixture_with_secret(EIGHT).await;
    let config = fixture.get(CONFIG).await;
    assert_eq!(source(&config, GROUP)["writable"], false);
    let locked = source(&config, &fixture.originals["locked.dae"]);
    let copied = format!("# {EIGHT} copied here\n");
    refused(&fixture, fixture.replace(locked, &copied)).await;
    refused(&fixture, create(&fixture, "config.d/copy.dae", &copied)).await;
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

/// Effective and overridden native and Clash values, in either spelling the listing masks.
#[tokio::test]
async fn every_masked_listener_secret_is_refused_in_written_content() {
    const QUOTED: &str = "old-\"quoted\"-clash-token";
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        std::fs::create_dir_all(root.join("config.d")).unwrap();
        let auth = files.get_mut("auth.dae").unwrap();
        *auth = auth.replace(
            &format!("secret: '{SECRET}'"),
            &format!("secret: 'overridden-listener-token'\n secret: '{SECRET}'"),
        );
        auth.push_str(&format!(
            "experimental {{ clash_api {{ secret: '{QUOTED}'\n secret: '{CLASH}' }} }}\n"
        ));
        let main = files.get_mut("main.dae").unwrap();
        *main = main.replace("'locked.dae'\n", "'locked.dae'\n 'config.d/*.dae'\n");
    })
    .await;
    let escaped = serde_json::to_string(QUOTED).unwrap();
    let escaped = &escaped[1..escaped.len() - 1];
    let config = fixture.get(CONFIG).await;
    let locked = source(&config, &fixture.originals["locked.dae"]);
    assert_eq!(locked["writable"], true);
    for value in [SECRET, CLASH, "overridden-listener-token", QUOTED, escaped] {
        let copied = format!("# {value} copied here\n");
        refused(&fixture, fixture.replace(locked, &copied)).await;
        refused(&fixture, create(&fixture, "config.d/copy.dae", &copied)).await;
    }
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

/// In db mode the stored secret survives only in the db, not in any accepted source text.
#[tokio::test]
async fn stored_listener_secret_is_refused_in_written_content_in_db_mode() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    let config = fixture.get(CONFIG).await;
    let editable = source(&config, &fixture.originals["editable.dae"]);
    let refused = error(
        fixture
            .replace(editable, &format!("# {SECRET}\n"))
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    assert_eq!(
        refused["error"]["details"],
        json!({"reason":"listener_secret_in_content"})
    );
    assert_eq!(store.head(), Ok(Some(1)));
    fixture.shutdown().await;
}
