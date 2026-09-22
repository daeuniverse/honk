use super::*;
use axum::{body::Body, response::IntoResponse};
use futures::{FutureExt, Stream, StreamExt};
use std::{io, process::Command, time::Duration};
use tracing_subscriber::prelude::*;

// Cache rebuilds are process-global; a parallel test without a default Dispatch can
// cache NoSubscriber's interest even while this test retains a scoped subscriber.
const ISOLATED: &str = "HONK_NATIVE_LOG_ISOLATED";

fn run_isolated(test_name: &str) -> bool {
    if std::env::var_os(ISOLATED).is_some() {
        return false;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(ISOLATED, "1")
        .output()
        .expect("isolated native log test");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

fn store() -> Arc<LogStore> {
    Arc::new(LogStore::new("log-instance".into(), true, "trace"))
}

fn capture(store: &Arc<LogStore>) -> tracing::Dispatch {
    let (layer, binding) = tracing_layer();
    binding.bind(Arc::downgrade(store));
    tracing::Dispatch::new(tracing_subscriber::registry().with(layer))
}

fn response(store: &Arc<LogStore>, query: &str, cursor: Option<&str>) -> Response {
    request(store, query, cursor).unwrap()
}

fn request(store: &Arc<LogStore>, query: &str, cursor: Option<&str>) -> Result<Response, ApiError> {
    let mut request = Request::builder().uri(format!("/api/v1/logs{query}"));
    if let Some(cursor) = cursor {
        request = request.header("last-event-id", cursor);
    }
    store.response(
        &request.body(Body::empty()).unwrap(),
        &RequestId("test".into()),
    )
}

async fn next(stream: &mut (impl Stream<Item = Result<Bytes, axum::Error>> + Unpin)) -> String {
    let frame = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    String::from_utf8(frame.to_vec()).unwrap()
}

fn cursor(frame: &str) -> &str {
    frame
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .unwrap()
}

fn data(frame: &str) -> Value {
    serde_json::from_str(
        frame
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap()
}

fn emit_nodes(dispatch: &tracing::Dispatch, nodes: u64) {
    tracing::dispatcher::with_default(dispatch, || {
        tracing::info!(target: "honk_core::control::runtime",
            message = "Publishing accepted subscription body", nodes);
    });
}

fn assert_expired(store: &Arc<LogStore>, query: &str, cursor: &str) {
    assert_eq!(
        request(store, query, Some(cursor))
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn tracing_retains_during_grace_and_resume_ready_cannot_skip_replay() {
    if run_isolated(
        "native_api::logs::tests::tracing_retains_during_grace_and_resume_ready_cannot_skip_replay",
    ) {
        return;
    }
    let mut config = honk_config::Config::default();
    config.global.log_level = "trace".into();
    let owner = super::super::observation::NativeObservation::new(&config);
    owner.settings.renew(&owner, false);
    let store = Arc::clone(&owner.logs);
    let dispatch = capture(&store);
    let mut stream = response(&store, "?level=info&target=honk_core::control", None)
        .into_body()
        .into_data_stream();
    let baseline = next(&mut stream).await;
    drop(stream);
    emit_nodes(&dispatch, 41);
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::debug!(target: "honk_core::control::runtime", "filtered severity");
        tracing::warn!(target: "Honk_core::control::runtime", "filtered case-sensitive target");
    });
    emit_nodes(&dispatch, 42);
    let mut resumed = response(
        &store,
        "?level=info&target=honk_core::control",
        Some(cursor(&baseline)),
    )
    .into_body()
    .into_data_stream();
    emit_nodes(&dispatch, 43);
    let ready = next(&mut resumed).await;
    assert!(ready.starts_with("event: stream.ready\n"));
    assert_eq!(cursor(&ready), cursor(&baseline));
    drop(resumed);

    // Disconnect immediately after ready must replay the same pending records.
    let mut resumed = response(
        &store,
        "?level=info&target=honk_core::control",
        Some(cursor(&ready)),
    )
    .into_body()
    .into_data_stream();
    next(&mut resumed).await;
    let first = next(&mut resumed).await;
    assert_eq!(data(&first)["fields"]["nodes"], 41);
    assert_eq!(data(&next(&mut resumed).await)["fields"]["nodes"], 42);
    assert_eq!(data(&next(&mut resumed).await)["fields"]["nodes"], 43);
    assert!(resumed.next().now_or_never().is_none());
    drop(resumed);
    let mut again = response(
        &store,
        "?level=info&target=honk_core::control",
        Some(cursor(&ready)),
    )
    .into_body()
    .into_data_stream();
    next(&mut again).await;
    assert_eq!(cursor(&next(&mut again).await), cursor(&first));
    assert_expired(
        &store,
        "?level=warn&target=honk_core::control",
        cursor(&ready),
    );
    assert_expired(&store, "?level=info&target=honk_core", cursor(&ready));
    assert_expired(
        &Arc::new(LogStore::new("other-instance".into(), true, "trace")),
        "?level=info&target=honk_core::control",
        cursor(&ready),
    );
    assert_expired(&store, "", "forged");
}

struct Unformattable;

impl fmt::Debug for Unformattable {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("native capture must not format arbitrary Debug values");
    }
}

impl fmt::Display for Unformattable {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("native capture must not format arbitrary Display values");
    }
}

#[tokio::test]
async fn actual_tracing_http_stream_withholds_untrusted_nested_messages_and_paths() {
    if run_isolated(
        "native_api::logs::tests::actual_tracing_http_stream_withholds_untrusted_nested_messages_and_paths",
    ) {
        return;
    }
    let store = store();
    let dispatch = capture(&store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let router = axum::Router::new()
        .route(
            "/api/v1/logs",
            axum::routing::get(
                |axum::extract::State(store): axum::extract::State<Arc<LogStore>>,
                 request: Request| async move {
                    store
                        .response(&request, &RequestId("http-test".into()))
                        .unwrap_or_else(IntoResponse::into_response)
                },
            ),
        )
        .with_state(Arc::clone(&store));
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut response = client
        .get(format!("http://{address}/api/v1/logs"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut received = String::new();
    while !received.contains("event: stream.ready") {
        received.push_str(std::str::from_utf8(&response.chunk().await.unwrap().unwrap()).unwrap());
    }
    let before = SystemTime::now();
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::error!(target: "honk_core::control::runtime",
            message = "Standalone DNS listener started", tcp = true, udp = false,
            password = "secret-credential", private_path = "/home/private/config.dae",
            nested = ?Unformattable, error = %Unformattable);
        tracing::warn!(target: "honk_core::control::runtime", nested = ?Unformattable,
            "token={} path={} nested={:?}", "secret-credential", "/home/private/config.dae", Unformattable);
        tracing::warn!(target: "foreign", message = "Standalone DNS listener started");
    });
    while received.matches("event: log\n").count() < 3 || !received.ends_with("\n\n") {
        let chunk = tokio::time::timeout(Duration::from_secs(1), response.chunk())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        received.push_str(std::str::from_utf8(&chunk).unwrap());
    }
    let records: Vec<_> = received
        .split("\n\n")
        .filter(|frame| frame.starts_with("event: log\n"))
        .map(data)
        .collect();
    assert_ne!(records[0]["message"], WITHHELD);
    assert_eq!(records[0]["fields"]["tcp"], true);
    assert_eq!(records[0]["fields"]["udp"], false);
    assert_eq!(records[0]["fields"]["native_withheld_fields"], true);
    assert_eq!(records[0]["target"], "honk_core::control::runtime");
    assert_eq!(records[0]["level"], "error");
    let observed =
        chrono::DateTime::parse_from_rfc3339(records[0]["ts"].as_str().unwrap()).unwrap();
    assert!(observed.timestamp() >= chrono::DateTime::<chrono::Utc>::from(before).timestamp());
    assert_eq!(records[1]["message"], WITHHELD);
    assert!(records[1]["fields"].is_null());
    assert_eq!(records[2]["message"], WITHHELD);
    assert!(!received.contains("secret-credential"));
    assert!(!received.contains("/home/private"));
    assert!(!received.contains("private_path"));
    store.shutdown();
    drop(response);
    stop.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn disabled_capture_skips_field_evaluation_and_dynamic_level_is_independent() {
    use std::sync::atomic::AtomicUsize;
    if run_isolated(
        "native_api::logs::tests::disabled_capture_skips_field_evaluation_and_dynamic_level_is_independent",
    ) {
        return;
    }
    let store = store();
    let (layer, binding) = tracing_layer();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::registry()
            .with(crate::console_log_layer(
                false,
                io::sink,
                tracing_subscriber::EnvFilter::new("error"),
            ))
            .with(layer),
    );
    tracing::dispatcher::set_global_default(dispatch).unwrap();
    let evaluated = AtomicUsize::new(0);
    let emit = || {
        tracing::debug!(target: "honk_core::control::runtime",
            nodes = { evaluated.fetch_add(1, Ordering::SeqCst); 7u64 },
            nested = ?Unformattable, error = %Unformattable, "debug");
    };
    emit();
    assert_eq!(evaluated.load(Ordering::SeqCst), 0);
    binding.bind(Arc::downgrade(&store));
    let mut stream = response(&store, "", None).into_body().into_data_stream();
    let baseline = next(&mut stream).await;
    emit();
    assert_eq!(data(&next(&mut stream).await)["level"], "debug");
    assert_eq!(evaluated.load(Ordering::SeqCst), 1);
    store.set_level("error");
    emit();
    assert_eq!(evaluated.load(Ordering::SeqCst), 1);
    store.set_level("trace");
    emit();
    assert_eq!(data(&next(&mut stream).await)["level"], "debug");
    store.set_recording(false);
    emit();
    assert_eq!(evaluated.load(Ordering::SeqCst), 2);
    assert!(stream.next().await.unwrap().is_err());
    store.set_recording(true);
    assert_expired(&store, "", cursor(&baseline));
    drop(stream);
    store.shutdown();
    emit();
    assert_eq!(evaluated.load(Ordering::SeqCst), 2);
    let weak = Arc::downgrade(&store);
    drop(store);
    assert!(weak.upgrade().is_none());
    emit();
    assert_eq!(evaluated.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn shrink_expires_evicted_cursors_and_queued_or_replaying_consumers() {
    if run_isolated(
        "native_api::logs::tests::shrink_expires_evicted_cursors_and_queued_or_replaying_consumers",
    ) {
        return;
    }
    let store = store();
    let dispatch = capture(&store);
    let mut live = response(&store, "", None).into_body().into_data_stream();
    let baseline = next(&mut live).await;
    drop(live);
    for nodes in 0..128 {
        emit_nodes(&dispatch, nodes);
    }
    let mut replay = response(&store, "", Some(cursor(&baseline)))
        .into_body()
        .into_data_stream();
    next(&mut replay).await;
    let first = next(&mut replay).await;
    store.set_limit(64);
    assert_expired(&store, "", cursor(&first));
    assert!(replay.next().await.unwrap().is_err());
    drop(replay);
    store.set_limit(128);
    let mut slow = response(&store, "?level=error", None)
        .into_body()
        .into_data_stream();
    next(&mut slow).await;
    tracing::dispatcher::with_default(&dispatch, || tracing::error!("queued error"));
    for nodes in 128..192 {
        emit_nodes(&dispatch, nodes);
    }
    store.set_limit(64);
    assert!(slow.next().await.unwrap().is_err());
    assert!(slow.next().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn log_expiry_heartbeat_capacity_and_overflow_use_shared_stream_rules() {
    if run_isolated(
        "native_api::logs::tests::log_expiry_heartbeat_capacity_and_overflow_use_shared_stream_rules",
    ) {
        return;
    }
    let store = store();
    let dispatch = capture(&store);
    let mut stream = response(&store, "", None).into_body().into_data_stream();
    let baseline = next(&mut stream).await;
    tokio::time::advance(Duration::from_secs(15)).await;
    assert_eq!(next(&mut stream).await, ": heartbeat\n\n");
    assert!(stream.next().now_or_never().is_none());
    let mut peers: Vec<_> = (0..15).map(|_| response(&store, "", None)).collect();
    assert_eq!(
        request(&store, "", None)
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    peers.pop();
    drop(response(&store, "", None));
    for nodes in 0..65 {
        emit_nodes(&dispatch, nodes);
    }
    assert!(stream.next().await.unwrap().is_err());
    drop(stream);
    for nodes in 65..513 {
        emit_nodes(&dispatch, nodes);
    }
    assert_expired(&store, "", cursor(&baseline));
    drop(peers);
    let mut fresh = response(&store, "", None).into_body().into_data_stream();
    let unexpired = next(&mut fresh).await;
    drop(fresh);
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_expired(&store, "", cursor(&unexpired));
}

#[test]
fn log_request_rejects_ambiguous_unknown_or_invalid_filters_before_streaming() {
    let store = store();
    for query in [
        "?level=verbose",
        "?level=info&level=error",
        "?target=",
        "?target=a&target=b",
        "?unknown=true",
    ] {
        assert_eq!(
            request(&store, query, None)
                .unwrap_err()
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
}
