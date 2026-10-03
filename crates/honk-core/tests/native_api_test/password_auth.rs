use super::*;

const USER: &str = "operator";
const PASSWORD: &str = "a-long-enough-password";

struct PasswordApp {
    app: TestApp,
    data: tempfile::TempDir,
}

impl std::ops::Deref for PasswordApp {
    type Target = TestApp;
    fn deref(&self) -> &TestApp {
        &self.app
    }
}

/// A password-mode listener with its own data directory, so these tests run independently.
async fn password_app() -> PasswordApp {
    let data = tempfile::tempdir().expect("temp data directory");
    let path = data.path().to_string_lossy().into_owned();
    let app = TestApp::new(|config| {
        config.global.data_dir = path;
        config.experimental.native_api.secret = String::new();
        config.experimental.native_api.password_auth = true;
    })
    .await;
    PasswordApp { app, data }
}

impl PasswordApp {
    /// Rows in the state db's `admin` table.
    fn administrators(&self) -> i64 {
        rusqlite::Connection::open(self.data.path().join("state/honk.db"))
            .unwrap()
            .query_row("SELECT count(*) FROM admin", [], |row| row.get(0))
            .unwrap()
    }

    async fn shutdown(self) {
        self.app.shutdown().await;
    }
}

async fn post_credentials(app: &TestApp, path: &str, user: &str, password: &str) -> Response {
    app.client
        .post(app.url(path))
        .json(&serde_json::json!({"username": user, "password": password}))
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_reports_the_mode_and_setup_state() {
    let app = password_app().await;
    // Discovery answers without a credential; version and capabilities still do not.
    let body: Value = app
        .client
        .get(app.url("/api"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "name": "daeuniverse/native",
            "api_major": 1,
            "links": {"auth_setup": "/api/v1/auth/setup", "auth_login": "/api/v1/auth/login"},
            "auth": {"mode": "password", "setup_required": true},
        }),
        "a caller without a session sees only how to sign in"
    );
    error_response(
        app.client
            .get(app.url("/api/v1/version"))
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    app.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_claims_the_one_account() {
    let app = password_app().await;
    // Before an administrator exists, login says so and protected resources stay closed.
    let refused = post_credentials(&app, "/api/v1/auth/login", USER, PASSWORD).await;
    error_response(refused, StatusCode::CONFLICT, "setup_required").await;
    let created = post_credentials(&app, "/api/v1/auth/setup", USER, PASSWORD).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let session: Value = created.json().await.unwrap();
    let token = session["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("hnk1_"));
    assert!(session["expires_at"].as_str().unwrap().ends_with('Z'));
    // The session is a bearer for every protected resource; anything else is not.
    assert_eq!(
        app.client
            .get(app.url("/api/v1/version"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    error_response(
        app.client
            .get(app.url("/api/v1/version"))
            .bearer_auth("hnk1_not-a-session")
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    // A second setup is refused whoever asks, and discovery stops asking for one.
    error_response(
        post_credentials(&app, "/api/v1/auth/setup", "other", PASSWORD).await,
        StatusCode::CONFLICT,
        "setup_already_completed",
    )
    .await;
    let discovery: Value = app
        .client
        .get(app.url("/api"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(discovery["auth"]["setup_required"], false);
    assert_eq!(discovery["status"], Value::Null);
    // A live session is admitted, so it gets the full view.
    let full: Value = app
        .client
        .get(app.url("/api"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(full["status"], "draft");
    assert_eq!(full["links"]["auth_logout"], "/api/v1/auth/logout");
    assert_eq!(full["auth"]["anonymous_loopback"], false);
    app.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn login_issues_a_session_and_logout_ends_only_that_one() {
    let app = password_app().await;
    let first: Value = post_credentials(&app, "/api/v1/auth/setup", USER, PASSWORD)
        .await
        .json()
        .await
        .unwrap();
    let token = first["token"].as_str().unwrap().to_owned();
    // A wrong password and a wrong username fail the same way.
    for (user, password) in [(USER, "a-different-password"), ("nobody", PASSWORD)] {
        error_response(
            post_credentials(&app, "/api/v1/auth/login", user, password).await,
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
        )
        .await;
    }
    let logged_in = post_credentials(&app, "/api/v1/auth/login", USER, PASSWORD).await;
    assert_eq!(logged_in.status(), StatusCode::OK);
    let second: Value = logged_in.json().await.unwrap();
    let second_token = second["token"].as_str().unwrap().to_owned();
    assert_ne!(second_token, token, "each login issues its own session");
    // Logout ends that session and leaves the other one alone.
    let out = app
        .client
        .post(app.url("/api/v1/auth/logout"))
        .bearer_auth(&second_token)
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), StatusCode::NO_CONTENT);
    error_response(
        app.client
            .get(app.url("/api/v1/version"))
            .bearer_auth(&second_token)
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    assert_eq!(
        app.client
            .get(app.url("/api/v1/version"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    app.shutdown().await;
}

/// Opens an authenticated stream and consumes its first frame.
async fn open_stream(app: &TestApp, path: &str, token: &str) -> Response {
    // The shared client's whole-request timeout would end any stream on its own.
    let mut response = contract::ContractClient(Client::builder().no_proxy().build().unwrap())
        .get(app.url(path))
        .bearer_auth(token)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        observations::next_event(&mut response, &mut String::new())
            .await
            .0,
        "stream.ready"
    );
    response
}

async fn assert_stream_ended(mut response: Response) {
    // A heartbeat is 15 seconds away, so a chunk inside IO_TIMEOUT can only be the end.
    let ended = timeout(IO_TIMEOUT, response.chunk())
        .await
        .expect("stream must end with its session");
    assert!(
        ended.as_ref().is_ok_and(Option::is_none)
            || ended.as_ref().is_err_and(|error| !error.is_timeout()),
        "{ended:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ending_a_session_closes_its_open_streams() {
    let app = password_app().await;
    let session: Value = post_credentials(&app, "/api/v1/auth/setup", USER, PASSWORD)
        .await
        .json()
        .await
        .unwrap();
    let token = session["token"].as_str().unwrap().to_owned();
    let events = open_stream(&app, "/api/v1/events?kinds=generation.changed", &token).await;
    let logs = open_stream(&app, "/api/v1/logs", &token).await;
    let out = app
        .client
        .post(app.url("/api/v1/auth/logout"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), StatusCode::NO_CONTENT);
    assert_stream_ended(events).await;
    assert_stream_ended(logs).await;
    app.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credentials_are_rejected_before_they_reach_the_store() {
    let app = password_app().await;
    // Wrong media type, unknown fields, a short password and a query parameter are all refused.
    let text = app
        .client
        .post(app.url("/api/v1/auth/setup"))
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await
        .unwrap();
    error_response(
        text,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    )
    .await;
    for (body, details) in [
        (
            json!({"username": USER, "password": PASSWORD, "role": "PRIVATE"}),
            json!({"field":"body","kind":"unknown_field"}),
        ),
        (
            json!({"username": USER, "password": "PRIVATE".repeat(600)}),
            json!({"field":"body","kind":"too_large"}),
        ),
    ] {
        let response = app
            .client
            .post(app.url("/api/v1/auth/setup"))
            .json(&body)
            .send()
            .await
            .unwrap();
        error_response_details(
            response,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            details,
        )
        .await;
    }
    error_response(
        post_credentials(&app, "/api/v1/auth/setup", USER, "short").await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    error_response(
        post_credentials(&app, "/api/v1/auth/setup", "not a name", PASSWORD).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    // A token in the query is a credential, and query credentials are never accepted.
    let queried = app
        .client
        .post(app.url("/api/v1/auth/setup?token=x"))
        .json(&serde_json::json!({"username": USER, "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    error_response(queried, StatusCode::UNAUTHORIZED, "authentication_required").await;
    assert_eq!(
        app.administrators(),
        0,
        "no account was created by a refused request"
    );
    app.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn token_mode_has_no_password_endpoints() {
    let app = TestApp::new(|_| {}).await;
    let body: Value = app.get("/api").send().await.unwrap().json().await.unwrap();
    assert_eq!(body["auth"]["mode"], "token");
    assert_eq!(body["auth"]["setup_required"], false);
    assert_eq!(body["links"]["auth_setup"], Value::Null);
    for path in ["/api/v1/auth/setup", "/api/v1/auth/login"] {
        let response = app
            .client
            .post(app.url(path))
            .json(&serde_json::json!({"username": USER, "password": PASSWORD}))
            .send()
            .await
            .unwrap();
        error_response(response, StatusCode::NOT_FOUND, "capability_not_supported").await;
    }
    app.shutdown().await;
}

#[tokio::test]
async fn credential_media_types_are_case_insensitive_but_not_duplicated() {
    for path in ["/api/v1/auth/setup", "/api/v1/auth/login"] {
        let app = password_app().await;
        let expected = if path.ends_with("/login") {
            assert_eq!(
                post_credentials(&app, "/api/v1/auth/setup", USER, PASSWORD)
                    .await
                    .status(),
                StatusCode::CREATED,
            );
            StatusCode::OK
        } else {
            StatusCode::CREATED
        };
        let body = json!({"username": USER, "password": PASSWORD}).to_string();
        let duplicate = app
            .client
            .post(app.url(path))
            .header("content-type", "application/json")
            .header("content-type", "text/plain")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        error_response_details(
            duplicate,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            json!({"header":"content-type","kind":"duplicate"}),
        )
        .await;
        let mixed_case = app
            .client
            .post(app.url(path))
            .header("content-type", "Application/JSON; charset=utf-8")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(mixed_case.status(), expected);
        app.shutdown().await;
    }
}
