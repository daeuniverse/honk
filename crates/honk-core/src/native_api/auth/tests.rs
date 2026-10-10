use super::storage::{Record, SetupError};
use super::*;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn pbkdf2_sha256_matches_independent_vectors() {
    // RFC 6070 inputs with HMAC-SHA256 (the values published for PBKDF2-HMAC-SHA256 test suites).
    assert_eq!(
        hex(&pbkdf2_sha256(b"password", b"salt", 1)),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    assert_eq!(
        hex(&pbkdf2_sha256(b"password", b"salt", 2)),
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    );
    assert_eq!(
        hex(&pbkdf2_sha256(b"password", b"salt", 4096)),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    );
}

#[test]
fn record_round_trips_and_verifies_in_constant_shape() {
    let record = Record::create("admin", "correct horse battery").unwrap();
    assert!(record.verify("admin", "correct horse battery"));
    assert!(!record.verify("admin", "correct horse batterx"));
    assert!(!record.verify("admin2", "correct horse battery"));
    let json = record.to_json();
    assert_eq!(Record::from_json(&json).unwrap(), record);
    assert!(Record::create("bad name", "correct horse battery").is_none());
    assert!(Record::create("admin", "short").is_none());
}

#[test]
fn passwords_are_eight_to_128_characters() {
    assert!(!valid_password("7 chars"));
    assert!(valid_password("8 chars!"));
    assert!(valid_password(&"x".repeat(128)));
    assert!(!valid_password(&"x".repeat(129)));
    // Counted in Unicode scalar values, so eight CJK characters are enough.
    assert!(valid_password("八個字元的密碼好"));
}

#[test]
fn record_parsing_rejects_unknown_shapes() {
    let mut json: serde_json::Value = serde_json::from_slice(
        &Record::create("a", "correct horse battery")
            .unwrap()
            .to_json(),
    )
    .unwrap();
    let ok = json.clone();
    json["iterations"] = serde_json::json!(4096);
    assert_eq!(
        Record::from_json(json.to_string().as_bytes()),
        Err(StoreError::Corrupt)
    );
    let mut json = ok.clone();
    json["algorithm"] = serde_json::json!("argon2id");
    assert_eq!(
        Record::from_json(json.to_string().as_bytes()),
        Err(StoreError::Corrupt)
    );
    let mut json = ok.clone();
    json["extra"] = serde_json::json!(1);
    assert_eq!(
        Record::from_json(json.to_string().as_bytes()),
        Err(StoreError::Corrupt)
    );
    let mut json = ok.clone();
    json["salt"] = serde_json::json!("AAAA");
    assert_eq!(
        Record::from_json(json.to_string().as_bytes()),
        Err(StoreError::Corrupt)
    );
    assert!(Record::from_json(ok.to_string().as_bytes()).is_ok());
}

fn temp_data_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

fn store_in(data: &Path) -> CredentialStore {
    CredentialStore::open(Arc::new(StateDb::open(data).unwrap())).unwrap()
}

fn admin_rows(data: &Path) -> i64 {
    StateDb::open(data)
        .unwrap()
        .strict()
        .query_row("SELECT count(*) FROM admin", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn setup_publishes_one_durable_account() {
    let data = temp_data_dir();
    let store = store_in(data.path());
    assert!(store.setup_required());
    assert!(!store.verify("admin", "correct horse battery"));
    store.setup("admin", "correct horse battery").unwrap();
    assert!(!store.setup_required());
    assert!(store.verify("admin", "correct horse battery"));
    assert_eq!(
        store.setup("other", "correct horse battery"),
        Err(SetupError::AlreadyCompleted)
    );
    assert_eq!(admin_rows(data.path()), 1);
    drop(store);
    // A fresh process reads the same account back.
    let reopened = store_in(data.path());
    assert!(!reopened.setup_required());
    assert!(reopened.verify("admin", "correct horse battery"));
}

#[test]
fn two_stores_racing_setup_yield_one_winner() {
    let data = temp_data_dir();
    let stores: Vec<_> = (0..2).map(|_| Arc::new(store_in(data.path()))).collect();
    let results: Vec<_> = stores
        .iter()
        .enumerate()
        .map(|(index, store)| {
            let store = Arc::clone(store);
            std::thread::spawn(move || {
                store.setup(&format!("admin{index}"), "correct horse battery")
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.contains(&Err(SetupError::AlreadyCompleted)));
    assert_eq!(admin_rows(data.path()), 1);
}

#[test]
fn a_refused_insert_leaves_setup_available() {
    let data = temp_data_dir();
    let db = Arc::new(StateDb::open(data.path()).unwrap());
    let store = CredentialStore::open(Arc::clone(&db)).unwrap();
    // The INSERT itself fails, after the transaction started.
    db.strict()
        .execute_batch(
            "CREATE TEMP TRIGGER refuse BEFORE INSERT ON admin BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .unwrap();
    assert_eq!(
        store.setup("admin", "correct horse battery"),
        Err(SetupError::Unavailable)
    );
    db.strict().execute_batch("DROP TRIGGER refuse").unwrap();
    assert!(store.setup_required());
    store.setup("admin", "correct horse battery").unwrap();
    assert!(store.verify("admin", "correct horse battery"));
}

/// The INSERT succeeds and leaves a deferred foreign key violation that fails COMMIT.
fn fail_commit(db: &StateDb) {
    db.strict()
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TEMP TABLE parent (id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE child (id INTEGER REFERENCES parent (id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TEMP TRIGGER orphan AFTER INSERT ON admin BEGIN INSERT INTO child VALUES (1); END;",
        )
        .unwrap();
}

#[test]
fn a_failed_commit_blocks_the_store() {
    let data = temp_data_dir();
    let db = Arc::new(StateDb::open(data.path()).unwrap());
    let store = CredentialStore::open(Arc::clone(&db)).unwrap();
    fail_commit(&db);
    assert_eq!(
        store.setup("admin", "correct horse battery"),
        Err(SetupError::NotDurable)
    );
    db.strict().execute_batch("DROP TRIGGER orphan").unwrap();
    assert!(
        !store.setup_required(),
        "an uncertain write must not offer setup"
    );
    assert!(!store.verify("admin", "correct horse battery"));
    assert_eq!(
        store.setup("admin", "correct horse battery"),
        Err(SetupError::AlreadyCompleted)
    );
}

#[test]
fn reset_refuses_while_a_daemon_has_the_db_open() {
    let data = temp_data_dir();
    let db = Arc::new(StateDb::open(data.path()).unwrap());
    let store = CredentialStore::open(Arc::clone(&db)).unwrap();
    store.setup("admin", "correct horse battery").unwrap();
    assert_eq!(
        crate::state::reset_admin(data.path()),
        Err(crate::state::StateError::InUse)
    );
    drop(store);
    drop(db);
    assert_eq!(crate::state::reset_admin(data.path()), Ok(true));
    assert!(store_in(data.path()).setup_required());
}

#[test]
fn session_expiry_revocation_and_capacity() {
    let sessions = Sessions::default();
    let now = Instant::now();
    let issued = sessions.issue_at(now, SystemTime::UNIX_EPOCH);
    assert!(issued.token.starts_with(TOKEN_PREFIX));
    assert_eq!(issued.expires_at, SystemTime::UNIX_EPOCH + SESSION_LIFETIME);
    assert!(sessions.authenticate_at(&issued.token, now).is_some());
    assert!(
        sessions
            .authenticate_at(
                &issued.token,
                now + SESSION_LIFETIME - Duration::from_secs(1)
            )
            .is_some()
    );
    assert!(
        sessions
            .authenticate_at(&issued.token, now + SESSION_LIFETIME)
            .is_none()
    );
    assert!(sessions.authenticate_at("hnk1_nope", now).is_none());
    assert!(sessions.authenticate_at(&issued.token[1..], now).is_none());
    assert!(sessions.revoke(&issued.token));
    assert!(!sessions.revoke(&issued.token));
    assert!(sessions.authenticate_at(&issued.token, now).is_none());
    let first = sessions.issue_at(now, SystemTime::UNIX_EPOCH);
    for i in 0..SESSION_LIMIT {
        sessions.issue_at(
            now + Duration::from_secs(i as u64 + 1),
            SystemTime::UNIX_EPOCH,
        );
    }
    assert_eq!(sessions.len(), SESSION_LIMIT);
    assert!(
        sessions.authenticate_at(&first.token, now).is_none(),
        "the oldest session is evicted"
    );
    let fresh = Sessions::default();
    assert!(
        fresh.authenticate_at(&first.token, now).is_none(),
        "a new process knows no session"
    );
}

async fn ends_soon(lease: SessionLease) -> bool {
    tokio::time::timeout(Duration::from_secs(1), lease.ended())
        .await
        .is_ok()
}

#[tokio::test]
async fn a_lease_ends_with_revocation_replacement_or_expiry() {
    let sessions = Sessions::default();
    let now = Instant::now();
    let kept = sessions.issue_at(now, SystemTime::UNIX_EPOCH);
    let live = sessions.authenticate_at(&kept.token, now).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), live.ended())
            .await
            .is_err(),
        "a live session keeps its lease"
    );
    let revoked = sessions.authenticate_at(&kept.token, now).unwrap();
    sessions.revoke(&kept.token);
    assert!(ends_soon(revoked).await);
    let oldest = sessions.issue_at(now, SystemTime::UNIX_EPOCH);
    let replaced = sessions.authenticate_at(&oldest.token, now).unwrap();
    for i in 0..SESSION_LIMIT {
        sessions.issue_at(
            now + Duration::from_secs(i as u64 + 1),
            SystemTime::UNIX_EPOCH,
        );
    }
    assert!(ends_soon(replaced).await);
    let expiring = Sessions::default();
    let issued_at = Instant::now() - SESSION_LIFETIME + Duration::from_millis(50);
    let issued = expiring.issue_at(issued_at, SystemTime::UNIX_EPOCH);
    let lease = expiring.authenticate_at(&issued.token, issued_at).unwrap();
    assert!(ends_soon(lease).await);
}

#[test]
fn admission_bounds_attempts_per_peer_and_overall() {
    let rate = AuthRate::default();
    let now = Instant::now();
    let a: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    let b: std::net::IpAddr = "10.0.0.3".parse().unwrap();
    for _ in 0..PEER_ATTEMPTS {
        assert_eq!(rate.admit_at(a, now), None);
    }
    assert!(rate.admit_at(a, now).is_some(), "the peer window closes");
    assert_eq!(
        rate.admit_at(b, now),
        None,
        "another peer has its own window"
    );
    // The global window closes after ten attempts however many peers there are.
    for i in 0..4 {
        let peer: std::net::IpAddr = format!("10.0.1.{i}").parse().unwrap();
        assert_eq!(rate.admit_at(peer, now), None);
    }
    let fresh: std::net::IpAddr = "10.0.2.1".parse().unwrap();
    assert!(
        rate.admit_at(fresh, now).is_some(),
        "the global window closes"
    );
    // Both windows reopen after a minute.
    assert_eq!(rate.admit_at(a, now + Duration::from_secs(61)), None);
}

#[test]
fn repeated_credential_failures_lock_logins_briefly() {
    let rate = AuthRate::default();
    let now = Instant::now();
    let peer: std::net::IpAddr = "192.168.1.5".parse().unwrap();
    for _ in 0..FAILURES_BEFORE_LOCK {
        rate.failed_at(now);
    }
    let wait = rate.admit_at(peer, now).expect("locked");
    assert!(wait <= LOCK.as_secs() as u32 && wait > 0);
    assert!(
        rate.admit_at(peer, now + LOCK).is_none(),
        "the lock expires"
    );
    rate.failed_at(now + LOCK);
    rate.succeeded();
    assert!(
        rate.admit_at(peer, now + LOCK).is_none(),
        "a success clears the count"
    );
}

#[test]
fn setup_peers_are_loopback_or_private_only() {
    use crate::native_api::Peer;
    use std::net::IpAddr;
    let allow = [
        "127.0.0.1",
        "::1",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.1.1",
        "fd00::1",
        "fe80::1",
    ];
    let deny = [
        "8.8.8.8",
        "1.1.1.1",
        "172.32.0.1",
        "100.64.0.1",
        "2001:db8::1",
        "fec0::1",
        "0.0.0.0",
        "224.0.0.1",
    ];
    for ip in allow {
        assert!(
            Peer(ip.parse::<IpAddr>().unwrap().to_canonical()).may_set_up(),
            "{ip} may set up"
        );
    }
    for ip in deny {
        assert!(
            !Peer(ip.parse::<IpAddr>().unwrap().to_canonical()).may_set_up(),
            "{ip} may not set up"
        );
    }
    // An IPv4-mapped peer is judged as the IPv4 address it carries.
    assert!(Peer("::ffff:10.0.0.1".parse::<IpAddr>().unwrap().to_canonical()).may_set_up());
    assert!(!Peer("::ffff:8.8.8.8".parse::<IpAddr>().unwrap().to_canonical()).may_set_up());
}

#[test]
fn a_busy_db_leaves_setup_available() {
    let data = temp_data_dir();
    let store = store_in(data.path());
    let holder = StateDb::open(data.path()).unwrap();
    let mut connection = holder.strict();
    let busy = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(
        store.setup("admin", "correct horse battery"),
        Err(SetupError::Unavailable)
    );
    drop(busy);
    drop(connection);
    store.setup("admin", "correct horse battery").unwrap();
    assert!(store.verify("admin", "correct horse battery"));
}

#[test]
fn reset_on_a_db_without_its_schema_finds_no_administrator() {
    use std::os::unix::fs::OpenOptionsExt as _;

    let data = temp_data_dir();
    let state = data.path().join(crate::state::STATE_DIR);
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A first start that stopped between creating the file and its schema.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(state.join(crate::state::DB_FILE))
        .unwrap();
    assert_eq!(crate::state::reset_admin(data.path()), Ok(false));
}

#[tokio::test]
async fn blocked_setup_keeps_discovery_live_and_shutdown_joins_dropped_work() {
    use crate::native_api::{NativeServer, router};
    use axum::body::Body;
    use tower::ServiceExt as _;

    let data = temp_data_dir();
    let db = Arc::new(StateDb::open(data.path()).unwrap());
    let auth = Arc::new(Auth::open(Arc::clone(&db)).unwrap());
    let mut state = crate::native_api::tests::state().await;
    Arc::get_mut(&mut state).unwrap().auth = Some(Arc::clone(&auth));
    let app = router(Arc::clone(&state)).layer(axum::Extension(Peer("127.0.0.1".parse().unwrap())));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = NativeServer::start(listener, state);
    let (locked, ready) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let _connection = db.strict();
        locked.send(()).unwrap();
        let _ = held.recv_timeout(Duration::from_secs(10));
    });
    ready.await.unwrap();
    let credentials = || {
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/auth/setup")
            .header("host", "127.0.0.1:9527")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct horse battery"}"#,
            ))
            .unwrap()
    };
    let started = Instant::now();
    let request = tokio::spawn(app.clone().oneshot(credentials()));
    tokio::time::timeout(Duration::from_secs(5), async {
        while auth.store.setup_required() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "setup blocked the runtime or discovery"
    );
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());

    let discovery = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api")
                .header("host", "127.0.0.1:9527")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(discovery.into_body(), 65536)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["auth"]["setup_required"], false);
    let busy = app.clone().oneshot(credentials()).await.unwrap();
    assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(busy.headers()["retry-after"], "1");

    let mut shutdown = tokio::spawn(server.shutdown());
    while !auth.work.lock().closed {
        tokio::task::yield_now().await;
    }
    let refused = app.oneshot(credentials()).await.unwrap();
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
            .await
            .is_err()
    );
    release.send(()).unwrap();
    holder.join().unwrap();
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .unwrap()
        .unwrap();
    assert!(auth.store.verify("admin", "correct horse battery"));
    assert_eq!(admin_rows(data.path()), 1);
}

#[tokio::test]
async fn an_unconfirmed_setup_write_is_not_retryable() {
    use crate::native_api::router;
    use axum::body::Body;
    use tower::ServiceExt as _;

    let data = temp_data_dir();
    let db = Arc::new(StateDb::open(data.path()).unwrap());
    let auth = Arc::new(Auth::open(Arc::clone(&db)).unwrap());
    let mut state = crate::native_api::tests::state().await;
    Arc::get_mut(&mut state).unwrap().auth = Some(auth);
    fail_commit(&db);
    let response = router(state)
        .layer(axum::Extension(Peer("127.0.0.1".parse().unwrap())))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/auth/setup")
                .header("host", "127.0.0.1:9527")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"admin","password":"correct horse battery"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("retry-after").is_none());
}
