//! Clash-compatible REST API server for zashboard / Metacubexd dashboards.
//!
//! Enabled via `experimental.clash_api.external_controller` and compiled in
//! with the `clash-api` cargo feature (on by default). Implements the
//! sing-box `experimental/clashapi` minimal endpoint set: proxies, rules,
//! connections, configs/mode, delay tests, cache flush, log/traffic
//! websocket streams (with a chunked-HTTP fallback for plain GET clients),
//! `/dns/query`, proxy providers, and optional external UI hosting with
//! automatic dashboard download.

pub mod doh;
pub mod logs;
pub mod ui;

use axum::{
    Router,
    body::Body,
    extract::{
        FromRequestParts, Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
};
use bytes::Bytes;
use honk_config::Config;
use honk_config::group::GroupPolicy;
use honk_config::node::{Group, Node};
use honk_config::types::NodeProtocol;
use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use honk_outbound::group::SelectionNetwork;
use honk_outbound::group::{GroupManager, SharedGroupManager};
use honk_outbound::urltest::{
    urltest_group_with_feedback, urltest_node_in_generation_with_feedback,
};
use std::sync::{Arc, Weak};
use std::time::Duration;

const STREAM_CHANNEL_CAPACITY: usize = 16;
const CONNECTION_INTERVAL_BUCKETS_MS: [u64; 9] =
    [100, 200, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000];

/// Lazily populated fan-out for high-frequency API streams. A sampler checks
/// receiver count before it snapshots or serializes any data.
pub struct StreamSamplers {
    connections: dashmap::DashMap<Duration, tokio::sync::broadcast::Sender<Arc<Bytes>>>,
    traffic: tokio::sync::broadcast::Sender<Arc<Bytes>>,
    traffic_started: std::sync::atomic::AtomicBool,
    memory: tokio::sync::broadcast::Sender<Arc<Bytes>>,
    memory_started: std::sync::atomic::AtomicBool,
}

impl StreamSamplers {
    pub fn new() -> Self {
        let (traffic, _) = tokio::sync::broadcast::channel(STREAM_CHANNEL_CAPACITY);
        let (memory, _) = tokio::sync::broadcast::channel(STREAM_CHANNEL_CAPACITY);
        Self {
            connections: dashmap::DashMap::new(),
            traffic,
            traffic_started: std::sync::atomic::AtomicBool::new(false),
            memory,
            memory_started: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl Default for StreamSamplers {
    fn default() -> Self {
        Self::new()
    }
}

use crate::mode::{DatapathFlagsHandle, ModeState, SharedModeState};

pub struct ClashState {
    pub config: Arc<tokio::sync::RwLock<Arc<Config>>>,
    pub stats: Arc<crate::stats::StatsManager>,
    pub alive_set: Arc<AliveDialerSet>,
    /// Hot-swappable group manager cell; a config reload swaps the inner
    /// manager and this API sees the new groups on the next request.
    pub group_manager: SharedGroupManager,
    pub cache_db: Option<Arc<crate::cachedb::CacheDb>>,
    pub connection_tracker: Arc<crate::connection_tracker::ConnectionTracker>,
    pub proxy_registry: Arc<honk_outbound::proxy::ProxyRegistry>,
    /// Hot-swappable runtime generation cell; delay measurements resolve
    /// their node's runtime through it so session protocols probe over the
    /// same generation-warm session the data path uses.
    pub runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    /// Shared clash mode + GLOBAL selection (also held by the control
    /// plane, which applies the mode override on the outbound path).
    pub mode_state: SharedModeState,
    /// Sole writer for mode/global persistence and datapath policy flags.
    pub datapath_flags: DatapathFlagsHandle,
    /// Bearer secret from `experimental.clash_api.secret`; empty = no auth.
    pub secret: String,
    /// Shared connection pool (ready-pool hit/miss metrics in `/stats`).
    pub connection_pool: Arc<crate::pool::ConnectionPool>,
    /// External UI directory (`experimental.clash_api.external_ui`).
    pub external_ui: String,
    /// Traffic router; the external-UI download routes its fetch through it
    /// like user traffic.
    pub router: Arc<tokio::sync::RwLock<crate::routing::Router>>,
    /// Active-level handle for the Clash API tracing layer.
    pub log_handle: logs::ClashLogHandle,
    pub dns_service: crate::dns::DnsService,
    /// Shared lazy samplers for high-fanout websocket/HTTP streams.
    pub stream_samplers: Arc<StreamSamplers>,
}

pub fn router(state: Arc<ClashState>) -> Router {
    let mut app = Router::new()
        .route("/", get(hello))
        .route("/version", get(version))
        .route(
            "/configs",
            get(get_configs).put(put_configs).patch(patch_configs),
        )
        .route("/proxies", get(get_proxies))
        .route("/proxies/{name}", get(get_proxy).put(put_proxy))
        .route("/proxies/{name}/delay", get(get_proxy_delay))
        .route("/group/{name}/delay", get(get_group_delay))
        .route("/rules", get(get_rules))
        .route(
            "/connections",
            get(get_connections).delete(delete_connections),
        )
        .route("/connections/{id}", delete(delete_connection))
        .route("/traffic", get(get_traffic))
        .route("/memory", get(get_memory))
        .route("/stats", get(get_outbound_stats))
        .route("/logs", get(get_logs))
        .route("/dns/query", get(get_dns_query))
        .route("/cache/fakeip/flush", post(flush_fakeip))
        .route("/cache/dns/flush", post(flush_dns))
        .route("/providers/proxies", get(get_proxy_providers))
        .route("/providers/rules", get(get_rule_providers))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // External UI hosting (outside auth, mirroring sing-box).
    if !state.external_ui.is_empty() {
        // sing-box server_resources.go: download the dashboard in the
        // background when the directory is missing/empty; ServeDir keeps
        // returning 404 until the files land (never blocks startup). The
        // fetch follows the traffic routing decision (direct/block/proxy).
        ui::spawn_ui_download_if_needed(ui::UiDownloadContext {
            external_ui: state.external_ui.clone(),
            router: state.router.clone(),
            config: state.config.clone(),
            group_manager: state.group_manager.clone(),
            proxy_registry: state.proxy_registry.clone(),
            runtime_registry: state.runtime_registry.clone(),
        });
        app = app
            // 301 Moved Permanently, matching sing-box's RedirectHandler.
            .route(
                "/ui",
                get(|| async {
                    Response::builder()
                        .status(StatusCode::MOVED_PERMANENTLY)
                        .header(header::LOCATION, "/ui/")
                        .body(axum::body::Body::empty())
                        .expect("static redirect response")
                }),
            )
            .nest_service(
                "/ui/",
                tower_http::services::ServeDir::new(&state.external_ui),
            );
    }

    // Dashboards are served from a different origin; allow cross-origin
    // calls the same way sing-box does (AccessControlAllowOrigin: *).
    app.layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state)
}

async fn bind_listener(
    listen: std::net::SocketAddr,
    connection_tracker: &crate::connection_tracker::ConnectionTracker,
) -> Option<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind(listen).await {
        Ok(listener) => {
            connection_tracker.enable();
            Some(listener)
        }
        Err(error) => {
            tracing::error!("clash API failed to bind {}: {}", listen, error);
            None
        }
    }
}

pub async fn serve(state: Arc<ClashState>, listen: std::net::SocketAddr) {
    let Some(listener) = bind_listener(listen, &state.connection_tracker).await else {
        return;
    };
    let app = router(state.clone());
    tracing::info!("clash API listening on http://{listen}");
    if let Err(error) = axum::serve(listener, app).await {
        tracing::error!("clash API server error: {}", error);
        state.connection_tracker.disable_api();
    }
}

/// Optional websocket upgrade: `None` when the request has no valid WS
/// handshake headers (plain GET). Used so endpoints can serve both the
/// JSON document and the WS stream on the same path.
struct MaybeWs(Option<WebSocketUpgrade>);

impl<S> FromRequestParts<S> for MaybeWs
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .ok(),
        ))
    }
}

/// When `secret` is configured, every request needs
/// `Authorization: Bearer <secret>` — except websocket upgrades, which may
/// pass `?token=<secret>` because browsers cannot set headers on WS
/// handshakes. The query token is percent-decoded before comparison so
/// secrets containing reserved characters (`+`, `=`, `&`, ...) match.
/// Failures get 401 `{"message":"Unauthorized"}`.
async fn auth_middleware(
    State(s): State<Arc<ClashState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    if s.secret.is_empty() {
        return next.run(req).await;
    }

    let is_ws_upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if is_ws_upgrade
        && let Some(token) = req
            .uri()
            .query()
            .and_then(|q| query_param(q, "token"))
            .filter(|t| !t.is_empty())
    {
        let decoded = percent_encoding::percent_decode_str(token).decode_utf8_lossy();
        if decoded.as_ref() == s.secret.as_str() {
            return next.run(req).await;
        }
        return unauthorized();
    }

    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|h| h == format!("Bearer {}", s.secret))
        .unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        unauthorized()
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"message": "Unauthorized"})),
    )
        .into_response()
}

/// Extract `key` from a raw `a=1&b=2` query string. The value is returned
/// verbatim (not percent-decoded); callers decode as needed — the WS auth
/// path percent-decodes the token before comparing it to the secret.
fn query_param<'q>(query: &'q str, key: &str) -> Option<&'q str> {
    query.split('&').find_map(|pair| {
        pair.split_once('=')
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v)
    })
}

/// JSON error body in the clash `{"message": ...}` shape.
fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({"message": message}))).into_response()
}

/// GET / — health check; redirects browsers to the UI when one is hosted.
async fn hello(State(s): State<Arc<ClashState>>, headers: HeaderMap) -> Response {
    let accepts_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("application/json"))
        .unwrap_or(false);
    if !s.external_ui.is_empty() && !accepts_json {
        // 302 Found, same as a dashboard would follow after login.
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/ui/")
            .body(axum::body::Body::empty())
            .expect("static redirect response");
    }
    Json(serde_json::json!({"hello": "clash"})).into_response()
}

/// GET /version — version info enabling premium/meta features in dashboards.
async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": concat!("honk ", env!("CARGO_PKG_VERSION")),
        "premium": true,
        "meta": true,
    }))
}

/// GET /configs — current configuration snapshot in Clash-compatible format.
async fn get_configs(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    let mode = s.mode_state.read().mode.clone();
    let config = s.config.read().await;
    Json(serde_json::json!({
        "mode": mode,
        "mode-list": ["Rule", "Global", "Direct"],
        "port": 0,
        "socks-port": 0,
        "mixed-port": 0,
        "allow-lan": false,
        "ipv6": false,
        "bind-address": "*",
        "log-level": config.global.log_level,
        "tun": {"enable": false},
    }))
}

/// PUT /configs — accept full config body (no-op for now).
async fn put_configs() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// PATCH /configs — update specific fields; `{mode}` switches the clash
/// mode (Rule/Global/Direct, case-insensitive) and persists it to cache.db.
/// The body is parsed regardless of Content-Type (dashboard parity).
async fn patch_configs(State(s): State<Arc<ClashState>>, body: Bytes) -> Response {
    let body: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if let Some(mode_str) = body.get("mode").and_then(|v| v.as_str()) {
        let Some(mode) = ModeState::normalize(mode_str) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid mode (expected Rule/Global/Direct)",
            );
        };
        if let Err(error) = s.datapath_flags.set_mode(&mode).await {
            tracing::error!(%error, mode = %mode, "failed to update clash mode");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to update clash mode",
            );
        }
        tracing::info!(%mode, "clash mode updated");
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Map a node protocol to a Clash-compatible type name.
fn clash_protocol_type(protocol: NodeProtocol) -> &'static str {
    match protocol {
        NodeProtocol::SS => "Shadowsocks",
        NodeProtocol::Trojan => "Trojan",
        NodeProtocol::VMess => "Vmess",
        NodeProtocol::VLess => "Vless",
        NodeProtocol::Socks5 => "Socks5",
        NodeProtocol::Hysteria2 => "Hysteria2",
        NodeProtocol::Tuic => "Tuic",
        NodeProtocol::Juicity => "Juicity",
        NodeProtocol::AnyTLS => "AnyTLS",
        NodeProtocol::Direct => "Direct",
        NodeProtocol::Block => "Reject",
    }
}

/// Map a GroupPolicy to a Clash-compatible type name.
fn clash_group_type(policy: GroupPolicy) -> &'static str {
    match policy {
        GroupPolicy::Selector => "selector",
        GroupPolicy::URLTest => "url_test",
        GroupPolicy::LoadBalance => "load_balance",
        GroupPolicy::Fallback => "fallback",
        GroupPolicy::Score => "url_test",
    }
}

/// Build a single proxy info object used by zashboard/Metacubexd for a group.
fn build_group_proxy_info(
    group: &Group,
    group_manager: &GroupManager,
    alive_set: &AliveDialerSet,
) -> serde_json::Value {
    let node_names = group_manager.node_names_in_group(&group.name);
    let now = match group.policy {
        GroupPolicy::Selector => group_manager
            .get_selector_choice(&group.name)
            .or_else(|| group.default.clone())
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
        GroupPolicy::URLTest => group_manager
            .get_urltest_selection(&group.name)
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
        // Round-robin has no stable selection to display; show the first.
        GroupPolicy::LoadBalance => node_names.first().cloned().unwrap_or_default(),
        GroupPolicy::Fallback => group_manager
            .get_fallback_selection(&group.name)
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
        GroupPolicy::Score => group_manager
            .get_score_selection_for_network(&group.name, SelectionNetwork::Tcp)
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
    };

    let mut history: Vec<serde_json::Value> = Vec::new();
    for name in &node_names {
        // Member tags may name sub-groups; only real nodes carry samples.
        let sample = group_manager
            .node_by_name(name)
            .and_then(|n| alive_set.get_last_real_sample(n.id, ProbeDomain::Tcp, IpVersion::V4));
        if let Some((latency, at)) = sample {
            history.push(delay_history_entry(latency.as_millis() as u64, at));
        }
    }

    serde_json::json!({
        "name": group.name,
        "type": clash_group_type(group.policy),
        "all": node_names,
        "now": now,
        "history": history,
    })
}

/// Build a proxy info object for an individual node.
///
/// Includes the per-node delay history (clash `{time, delay}` shape) so
/// dashboards can render per-node latencies — group members included.
fn build_node_proxy_info(node: &Node, alive_set: &AliveDialerSet) -> serde_json::Value {
    let mut info = serde_json::json!({
        "name": node.name,
        "type": clash_protocol_type(node.protocol()),
        "udp": true,
        "history": [],
    });
    if let Some((latency, at)) =
        alive_set.get_last_real_sample(node.id, ProbeDomain::Tcp, IpVersion::V4)
    {
        let ms = latency.as_millis() as u64;
        info["history"] = serde_json::json!([delay_history_entry(ms, at)]);
    }
    info
}

/// A clash-shaped delay history entry: the measurement's own wall-clock
/// time, not the render time (dashboards treat "now" timestamps as fresh).
fn delay_history_entry(ms: u64, at: std::time::SystemTime) -> serde_json::Value {
    serde_json::json!({
        "time": chrono::DateTime::<chrono::Utc>::from(at).to_rfc3339(),
        "delay": ms,
    })
}

/// Build the synthetic GLOBAL selector from concrete configured groups and
/// nodes. Every `all` member resolves to a top-level proxy document.
fn build_global_proxy_info(config: &Config, global_selection: &str) -> serde_json::Value {
    let mut all: Vec<String> = Vec::new();
    let mut push_unique = |name: &str| {
        if name != "Direct" && name != "Block" && !all.iter().any(|n| n == name) {
            all.push(name.to_string());
        }
    };
    for group in &config.groups {
        push_unique(&group.name);
    }
    for node in &config.nodes {
        push_unique(&node.name);
    }
    let now = all
        .iter()
        .find(|name| name.as_str() == global_selection)
        .or_else(|| all.first())
        .map(String::as_str)
        .unwrap_or("");
    serde_json::json!({
        "name": "GLOBAL",
        "type": "selector",
        "all": all,
        "now": now,
    })
}

async fn get_proxies(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    let config = s.config.read().await;
    let global_selection = s.mode_state.read().global_selection.clone();
    let group_manager = s.group_manager.read().clone();
    let mut proxies = serde_json::Map::new();

    // Emit every node as a top-level proxy — including group members. Clash
    // dashboards resolve group members through these entries to display node
    // names and per-node delay history (real Clash behaves the same way).
    for node in &config.nodes {
        proxies.insert(node.name.clone(), build_node_proxy_info(node, &s.alive_set));
    }

    for group in &config.groups {
        proxies.insert(
            group.name.clone(),
            build_group_proxy_info(group, &group_manager, &s.alive_set),
        );
    }

    proxies.insert(
        "GLOBAL".to_string(),
        build_global_proxy_info(&config, &global_selection),
    );

    Json(serde_json::json!({"proxies": proxies}))
}

async fn get_proxy(State(s): State<Arc<ClashState>>, Path(name): Path<String>) -> Response {
    let config = s.config.read().await;
    let group_manager = s.group_manager.read().clone();

    if name == "GLOBAL" {
        let global_selection = s.mode_state.read().global_selection.clone();
        return Json(build_global_proxy_info(&config, &global_selection)).into_response();
    }

    if let Some(group) = config.groups.iter().find(|g| g.name == name) {
        return Json(build_group_proxy_info(group, &group_manager, &s.alive_set)).into_response();
    }

    if let Some(node) = config.nodes.iter().find(|n| n.name == name) {
        return Json(build_node_proxy_info(node, &s.alive_set)).into_response();
    }

    error_response(StatusCode::NOT_FOUND, "proxy not found")
}

/// Body for `/proxies/{name}` PUT: `{"name": "target_node"}`.
#[derive(Debug, serde::Deserialize)]
struct PutProxyBody {
    name: String,
}

async fn put_proxy(
    State(s): State<Arc<ClashState>>,
    Path(group_name): Path<String>,
    body: Bytes,
) -> Response {
    // Dashboards (metacubexd/zashboard) PUT the selection without a JSON
    // Content-Type; accept any content type (mihomo parity) and fail only
    // on a genuinely malformed body.
    let body: PutProxyBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    // GLOBAL is a synthetic selector backed by the shared mode state.
    if group_name == "GLOBAL" {
        let config = s.config.read().await;
        let valid = config.groups.iter().any(|g| g.name == body.name)
            || config.nodes.iter().any(|n| n.name == body.name);
        drop(config);
        if !valid {
            return error_response(StatusCode::BAD_REQUEST, "unknown proxy name");
        }
        if let Err(error) = s
            .datapath_flags
            .set_global_selection(body.name.clone())
            .await
        {
            tracing::error!(%error, selection = %body.name, "failed to update GLOBAL selection");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to update GLOBAL selection",
            );
        }
        return StatusCode::NO_CONTENT.into_response();
    }

    let config = s.config.read().await;
    let Some(group) = config.groups.iter().find(|g| g.name == group_name) else {
        return error_response(StatusCode::NOT_FOUND, "group not found");
    };
    if group.policy != GroupPolicy::Selector {
        return error_response(StatusCode::BAD_REQUEST, "must be a Selector group");
    }
    // Members are member TAGS (node names + nested sub-group tags): picking
    // a sub-group defers to its own selection (sing-box drill-down). A leaf
    // inside a sub-group is not a direct member and is rejected here.
    let is_member = {
        let gm = s.group_manager.read();
        gm.node_names_in_group(&group_name)
            .iter()
            .any(|t| t == &body.name)
    };
    drop(config);
    if !is_member {
        return error_response(StatusCode::BAD_REQUEST, "node is not a member of the group");
    }

    // cache.db persistence runs through the group manager's persist
    // callback, wired by ControlPlane::init_cache_db.
    s.group_manager
        .read()
        .set_selector_choice(&group_name, &body.name);
    StatusCode::NO_CONTENT.into_response()
}

/// Query params for delay endpoints: `?url=<url>&timeout=<ms>`.
#[derive(Debug, serde::Deserialize)]
struct DelayQuery {
    #[serde(default)]
    url: String,
    #[serde(default)]
    timeout: Option<u64>,
}

impl DelayQuery {
    fn timeout(&self) -> Duration {
        // Zero means "use the urltest default" (the measurement normalizes it).
        self.timeout
            .map(Duration::from_millis)
            .unwrap_or(Duration::ZERO)
    }
}

/// Clamp a measured latency to clash's uint16 delay range.
fn delay_ms(d: Duration) -> u64 {
    (d.as_millis() as u64).min(u16::MAX as u64)
}

/// GET /proxies/{name}/delay — live latency measurement (HEAD request
/// through the node / group members). Successes refresh the alive-set
/// history; failures return 503, but only the second consecutive failure
/// adds a synthetic penalty and demotes the node.
async fn get_proxy_delay(
    State(s): State<Arc<ClashState>>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> Response {
    let config = s.config.read().await;

    if let Some(node) = config.nodes.iter().find(|n| n.name == name).cloned() {
        drop(config);
        let Some(entry) = s.proxy_registry.find(node.protocol()) else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "no handler for the node protocol",
            );
        };
        let tcp = entry.tcp.clone();
        let warmable = entry.warmable.clone();
        let generation = s.runtime_registry.read().clone();
        let measured = {
            let group_manager = s.group_manager.read().clone();
            urltest_node_in_generation_with_feedback(
                &generation,
                &node,
                tcp.as_ref(),
                warmable.as_deref(),
                &query.url,
                query.timeout(),
                &group_manager,
            )
            .await
        };
        return match measured {
            Ok(latency) => {
                s.alive_set
                    .record_probe_latency(node.id, ProbeDomain::Tcp, IpVersion::V4, latency);
                Json(serde_json::json!({"delay": delay_ms(latency)})).into_response()
            }
            Err(e) => {
                // A lone failure leaves history unchanged; a second
                // consecutive failure adds the synthetic penalty and
                // demotes the node.
                s.alive_set
                    .record_dial_failure(node.id, ProbeDomain::Tcp, IpVersion::V4);
                error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!("An error occurred in the delay test: {e}"),
                )
            }
        };
    }

    let is_group = config.groups.iter().any(|group| group.name == name);
    drop(config);
    if is_group {
        let members = {
            let gm = s.group_manager.read();
            gm.delay_test_members(&name)
        };
        if members.is_empty() {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "group has no members");
        }
        let leaves: Vec<Node> = members.iter().map(|(_, leaf)| leaf.clone()).collect();
        let generation = s.runtime_registry.read().clone();
        let results = {
            let group_manager = s.group_manager.read().clone();
            urltest_group_with_feedback(
                &leaves,
                &generation,
                &s.proxy_registry,
                &s.alive_set,
                &query.url,
                query.timeout(),
                group_manager,
            )
            .await
        };
        // sing-box performUpdateCheck: an explicit delay test immediately
        // re-evaluates the URLTest selection with the fresh measurements
        // (tolerance hysteresis applies). Without this the group's `now`
        // would only update on the next real dial.
        {
            let gm = s.group_manager.read().clone();
            if gm.get_group_policy(&name) == Some(GroupPolicy::URLTest) {
                let _ = gm.select_node_for_domain(&name, ProbeDomain::Tcp, IpVersion::V4);
            }
        }
        // The current selection is a member TAG (node name or sub-group
        // tag); its delay is the measurement of that member's leaf.
        let current = {
            let gm = s.group_manager.read();
            gm.get_selector_choice(&name)
                .or_else(|| gm.get_urltest_selection(&name))
                .or_else(|| gm.get_score_selection_for_network(&name, SelectionNetwork::Tcp))
        }
        .or_else(|| members.first().map(|(tag, _)| tag.clone()));
        if let Some(current) = current
            && let Some((_, leaf)) = members.iter().find(|(tag, _)| tag == &current)
            && let Some((_, Ok(latency))) = results.iter().find(|(n, _)| n == &leaf.name)
        {
            return Json(serde_json::json!({"delay": delay_ms(*latency)})).into_response();
        }
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "An error occurred in the delay test",
        );
    }

    error_response(StatusCode::NOT_FOUND, "proxy not found")
}

/// GET /group/{name}/delay — clash-meta group delay test: measures every
/// member concurrently and returns `{"<memberTag>": ms, ...}`; failed
/// members are omitted (sing-box api_meta_group.go semantics). Nested
/// sub-groups are measured through their representative leaf and reported
/// under their own tag.
async fn get_group_delay(
    State(s): State<Arc<ClashState>>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> Response {
    let exists = {
        let config = s.config.read().await;
        config.groups.iter().any(|group| group.name == name)
    };
    if !exists {
        return error_response(StatusCode::NOT_FOUND, "group not found");
    }
    let members = {
        let gm = s.group_manager.read();
        gm.delay_test_members(&name)
    };

    let leaves: Vec<Node> = members.iter().map(|(_, leaf)| leaf.clone()).collect();
    let generation = s.runtime_registry.read().clone();
    let results = {
        let group_manager = s.group_manager.read().clone();
        urltest_group_with_feedback(
            &leaves,
            &generation,
            &s.proxy_registry,
            &s.alive_set,
            &query.url,
            query.timeout(),
            group_manager,
        )
        .await
    };
    // sing-box performUpdateCheck: re-evaluate the URLTest selection with
    // the fresh measurements (see get_proxy_delay's group branch).
    {
        let gm = s.group_manager.read().clone();
        if gm.get_group_policy(&name) == Some(GroupPolicy::URLTest) {
            let _ = gm.select_node_for_domain(&name, ProbeDomain::Tcp, IpVersion::V4);
        }
    }
    let mut delays = serde_json::Map::new();
    for (tag, leaf) in &members {
        if let Some((_, Ok(latency))) = results.iter().find(|(n, _)| n == &leaf.name) {
            delays.insert(tag.clone(), serde_json::json!(delay_ms(*latency)));
        }
    }
    Json(serde_json::Value::Object(delays)).into_response()
}

async fn get_rules(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    let config = s.config.read().await;
    let rules = config
        .routing
        .rules
        .iter()
        .map(|rule| {
            let display = config.routing.clash_rule_display(rule);
            serde_json::json!({
                "type": display.rule_type(),
                "payload": display.payload(),
                "proxy": rule.outbound.as_str(),
            })
        })
        .collect::<Vec<_>>();

    Json(serde_json::json!({"rules": rules}))
}

fn udp_histogram_json(histogram: &crate::stats::UdpLatencyHistogramSnapshot) -> serde_json::Value {
    // The source histogram is a fixed 64-element atomic array. Snapshot
    // serialization allocates only this response array; it does not create
    // labels or unbounded metric state on the packet path.
    serde_json::json!({
        "count": histogram.count,
        "sumNanos": histogram.sum_nanos,
        "buckets": histogram.buckets.to_vec(),
    })
}

/// Per-outbound counters from the userspace stats manager (the datum the
/// retired debug API exposed at `/debug/stats`). Not part of the clash API
/// standard; handy for headless ops.
async fn get_outbound_stats(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    let snap = s.stats.snapshot();
    let (score_groups, score_cache) = {
        let group_manager = s.group_manager.read();
        (
            group_manager.score_reason_snapshot(),
            group_manager.score_cache_snapshot(),
        )
    };
    let score_groups: Vec<_> = score_groups
        .into_iter()
        .map(|group| {
            let counters = |counters: honk_outbound::group::ScoreReasonCounters| {
                serde_json::json!({
                    "coldExplore": counters.cold_explore,
                    "periodicExplore": counters.periodic_explore,
                    "reliabilityWinner": counters.reliability_winner,
                    "performanceWinner": counters.performance_winner,
                    "incumbentHeld": counters.incumbent_held,
                    "freshFailureBypass": counters.fresh_failure_bypass,
                    "deadFiltered": counters.dead_filtered,
                    "switchFlap": counters.switch_flap,
                    "failStreakExcluded": counters.fail_streak_excluded,
                    "exploreBackedOff": counters.explore_backed_off,
                })
            };
            serde_json::json!({
                "name": group.name,
                "tcp": counters(group.tcp),
                "udp": counters(group.udp),
            })
        })
        .collect();
    let per_outbound: Vec<serde_json::Value> = snap
        .iter()
        .map(|(name, v)| {
            serde_json::json!({
                "name": name,
                "totalConns": v.total_conns,
                "activeConns": v.active_conns,
                "upload": v.tx_bytes,
                "download": v.rx_bytes,
                "errors": v.errors,
            })
        })
        .collect();
    let pool = s.connection_pool.ready_metrics();
    let tcp = s.stats.tcp_snapshot();
    let udp = s.stats.udp_snapshot();
    let warm = s
        .stats
        .warm_snapshot(&s.runtime_registry.read().clone(), &s.connection_pool);
    let quic = honk_outbound::quic::quic_stats_snapshot();
    Json(serde_json::json!({
        "outbounds": per_outbound,
        "score": {
            "groups": score_groups,
            "cache": {
                "exactCells": score_cache.exact_cells,
                "aggregateCells": score_cache.aggregate_cells,
                "exactEvictions": score_cache.exact_evictions,
                "aggregateEvictions": score_cache.aggregate_evictions,
            },
        },
        "pool": {
            "readyHits": pool.hits,
            "readyMisses": pool.misses,
            "entries": pool.entries,
        },
        "quic": {
            "activeConnections": quic.active_connections,
            "srttUs": quic.srtt_us,
            "cwndBytes": quic.cwnd_bytes,
            "lossRatePpm": quic.loss_rate_ppm,
            "sentPackets": quic.sent_packets,
            "ackFrames": quic.ack_frames,
            "lostPackets": quic.lost_packets,
            "sentPlpmtudProbes": quic.sent_plpmtud_probes,
            "lostPlpmtudProbes": quic.lost_plpmtud_probes,
            "currentMtu": quic.current_mtu,
            "blackHoles": quic.black_holes,
            "congestionEvents": quic.congestion_events,
            "txBytes": quic.tx_bytes,
            "rxBytes": quic.rx_bytes,
            "txDatagrams": quic.tx_datagrams,
            "rxDatagrams": quic.rx_datagrams,
            "txIos": quic.tx_ios,
            "rxIos": quic.rx_ios,
            "transportTxWouldBlock": quic.transport_tx_would_block,
            "transportTxDrops": quic.transport_tx_drops,
            "transportRxDrops": quic.transport_rx_drops,
            "sessionRxDrops": quic.session_rx_drops,
            "sendTimeouts": quic.send_timeouts,
            "pathStalls": quic.path_stalls,
        },
        "warm": {
            "nodes": {
                "preconnect": warm.preconnect_nodes,
                "health": warm.health_nodes,
                "udp": warm.udp_nodes,
                "selector": warm.selector_nodes,
                "traffic": warm.traffic_nodes,
            },
            "sessions": {
                "anytls": warm.anytls_sessions,
                "vless": warm.vless_sessions,
                "tuic": warm.tuic_clients,
                "juicity": warm.juicity_clients,
                "hysteria2": warm.hysteria2_clients,
            },
        },
        "tcp": {
            "activeFlows": tcp.active_flows,
            "limit": tcp.limit,
            "capacity": {
                "rejected": tcp.capacity_rejections,
            },
        },
        "udp": {
            "endpoint": {
                "hits": udp.endpoint_hits,
                "misses": udp.endpoint_misses,
            },
            "latency": {
                "route": udp_histogram_json(&udp.route_latency),
                "dial": udp_histogram_json(&udp.dial_latency),
                "replyReady": udp_histogram_json(&udp.reply_ready_latency),
                "firstSend": udp_histogram_json(&udp.first_send_latency),
                "firstReply": udp_histogram_json(&udp.first_reply_latency),
            },
            "capacity": {
                "rejected": udp.capacity_rejections,
            },
            "slowPermit": {
                "accepted": udp.slow_permit_accepted,
                "rejected": udp.slow_permit_rejected,
                "closed": udp.slow_permit_closed,
            },
            "queue": {
                "accepted": udp.queue_accepted,
                "full": udp.queue_full,
                "flowFull": udp.flow_queue_full,
                "globalPayloadFull": udp.global_payload_full,
                "closed": udp.queue_closed,
            },
            "firstSend": {
                "failures": udp.first_send_failures,
            },
            "stagger": {
                "attempts": udp.stagger_attempts,
                "winners": udp.stagger_winners,
                "cancellations": udp.stagger_cancellations,
            },
            "warm": {
                "attempts": udp.warm_attempts,
                "successes": udp.warm_successes,
                "failures": udp.warm_failures,
            },
            "nfqueue": {
                "received": udp.nfqueue.received,
                "activeFlows": udp.nfqueue.active_flows,
                "kernelQueueDepth": udp.nfqueue.kernel_queue_depth,
                "kernelStatsAvailable": udp.nfqueue.kernel_stats_available,
                "kernelStatsReadErrors": udp.nfqueue.kernel_stats_read_errors,
                "kernelDropped": udp.nfqueue.kernel_dropped,
                "kernelUserDropped": udp.nfqueue.kernel_user_dropped,
                "heldPackets": udp.nfqueue.held_packets,
                "heldPeak": udp.nfqueue.held_peak,
                "socketReceiveBufferBytes": udp.nfqueue.socket_receive_buffer_bytes,
                "actorQueueFull": udp.nfqueue.actor_queue_full,
                "correlatorFull": udp.nfqueue.correlator_full,
                "actorQueueDepth": udp.nfqueue.actor_queue_depth,
                "actorQueuedBytes": udp.nfqueue.actor_queued_bytes,
                "actorOldestAgeNanos": udp.nfqueue.actor_oldest_age_nanos,
                "directAccepted": udp.nfqueue.direct_accepted,
                "proxyCopied": udp.nfqueue.proxy_copied,
                "proxyDropped": udp.nfqueue.proxy_dropped,
                "block": udp.nfqueue.block,
                "cancel": udp.nfqueue.cancel,
                "drop": udp.nfqueue.drop,
                "tokenMismatch": udp.nfqueue.token_mismatch,
                "tokenExhaustion": udp.nfqueue.token_exhaustion,
                "tokenRollovers": udp.nfqueue.token_rollovers,
                "verdictErrors": udp.nfqueue.verdict_errors,
                "receiptToVerdict": udp_histogram_json(&udp.nfqueue.receipt_to_verdict_latency),
            },
        },
    }))
}

#[derive(Debug, serde::Deserialize)]
struct ConnectionsQuery {
    /// WS push interval in milliseconds (default 1000).
    #[serde(default)]
    interval: Option<u64>,
}

/// Build the clash connections document from the tracker snapshot.
fn connections_json(s: &ClashState) -> serde_json::Value {
    connections_json_tracker(&s.connection_tracker)
}

fn connection_addr_parts(raw: &str) -> (String, String) {
    raw.parse::<std::net::SocketAddr>()
        .map(|addr| (addr.ip().to_string(), addr.port().to_string()))
        .unwrap_or_default()
}

fn connections_json_tracker(
    tracker: &crate::connection_tracker::ConnectionTracker,
) -> serde_json::Value {
    let snapshots = tracker.snapshot();
    let connections: Vec<serde_json::Value> = snapshots
        .iter()
        .map(|e| {
            let (src_ip, src_port) = connection_addr_parts(&e.source);
            let (dst_ip, dst_port) = connection_addr_parts(&e.destination);
            let start = std::time::SystemTime::now()
                .checked_sub(e.start_time.elapsed())
                .map(|time| chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339())
                .unwrap_or_default();

            let mut metadata = serde_json::json!({
                "network": &e.network,
                "type": &e.network,
                "sourceIP": src_ip,
                "destinationIP": dst_ip,
                "sourcePort": src_port,
                "destinationPort": dst_port,
                "host": e.domain.clone().unwrap_or_default(),
                "dnsMode": "normal",
            });
            // mihomo always emits both process keys (empty when unattributed);
            // zashboard's accessor does processPath.replace(...) unguarded, so
            // omitting them breaks its connection detail dialog.
            metadata["process"] = serde_json::Value::String(e.process.clone().unwrap_or_default());
            metadata["processPath"] =
                serde_json::Value::String(e.process_path.clone().unwrap_or_default());

            serde_json::json!({
                "id": e.id,
                "metadata": metadata,
                "upload": e.upload,
                "download": e.download,
                "start": start,
                "chains": e.chains,
                "rule": e.rule,
                "rulePayload": e.rule_payload,
            })
        })
        .collect();

    let (upload, download) = snapshots
        .iter()
        .fold((0, 0), |(up, down), e| (up + e.upload, down + e.download));
    serde_json::json!({
        "downloadTotal": download,
        "uploadTotal": upload,
        "connections": connections,
        "memory": rss_bytes(),
    })
}

async fn get_connections(
    State(s): State<Arc<ClashState>>,
    Query(query): Query<ConnectionsQuery>,
    ws: MaybeWs,
) -> Response {
    if let Some(ws) = ws.0 {
        let interval = normalize_connection_interval(query.interval);
        return ws.on_upgrade(move |socket| connections_ws(socket, s, interval));
    }
    Json(connections_json(&s)).into_response()
}

/// Push the full connections snapshot every `interval` until the client
/// disconnects.
async fn connections_ws(mut socket: WebSocket, s: Arc<ClashState>, interval: Duration) {
    let mut frames = connection_sampler(&s, interval);
    loop {
        match frames.recv().await {
            Ok(frame) => {
                if socket
                    .send(Message::Text(
                        std::str::from_utf8(frame.as_ref())
                            .expect("connections JSON is UTF-8")
                            .into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn normalize_connection_interval(requested_ms: Option<u64>) -> Duration {
    let requested_ms = requested_ms.unwrap_or(1_000);
    let bucket_ms = CONNECTION_INTERVAL_BUCKETS_MS
        .iter()
        .copied()
        .find(|bucket| requested_ms <= *bucket)
        .unwrap_or(CONNECTION_INTERVAL_BUCKETS_MS[CONNECTION_INTERVAL_BUCKETS_MS.len() - 1]);
    Duration::from_millis(bucket_ms)
}

fn connection_sampler(
    s: &Arc<ClashState>,
    interval: Duration,
) -> tokio::sync::broadcast::Receiver<Arc<Bytes>> {
    subscribe_connection_sampler(
        &s.stream_samplers,
        Arc::clone(&s.connection_tracker),
        interval,
    )
}

fn subscribe_connection_sampler(
    samplers: &Arc<StreamSamplers>,
    tracker: Arc<crate::connection_tracker::ConnectionTracker>,
    interval: Duration,
) -> tokio::sync::broadcast::Receiver<Arc<Bytes>> {
    match samplers.connections.entry(interval) {
        dashmap::mapref::entry::Entry::Occupied(entry) => entry.get().subscribe(),
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            let (tx, receiver) =
                tokio::sync::broadcast::channel::<Arc<Bytes>>(STREAM_CHANNEL_CAPACITY);
            entry.insert(tx.clone());
            spawn_connection_sampler(Arc::downgrade(samplers), tracker, interval, tx);
            receiver
        }
    }
}

struct ConnectionSamplerTaskGuard {
    samplers: Weak<StreamSamplers>,
    interval: Duration,
    tx: tokio::sync::broadcast::Sender<Arc<Bytes>>,
}

impl Drop for ConnectionSamplerTaskGuard {
    fn drop(&mut self) {
        if let Some(samplers) = self.samplers.upgrade() {
            samplers
                .connections
                .remove_if(&self.interval, |_, current| current.same_channel(&self.tx));
        }
    }
}

fn spawn_connection_sampler(
    samplers: Weak<StreamSamplers>,
    tracker: Arc<crate::connection_tracker::ConnectionTracker>,
    interval: Duration,
    tx: tokio::sync::broadcast::Sender<Arc<Bytes>>,
) {
    tokio::spawn(async move {
        let _task_guard = ConnectionSamplerTaskGuard {
            samplers: samplers.clone(),
            interval,
            tx: tx.clone(),
        };
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if tx.receiver_count() == 0 {
                let Some(samplers) = samplers.upgrade() else {
                    break;
                };
                if samplers
                    .connections
                    .remove_if(&interval, |_, current| {
                        current.same_channel(&tx) && current.receiver_count() == 0
                    })
                    .is_some()
                {
                    break;
                }
            }
            let frame = Arc::new(Bytes::from(connections_json_tracker(&tracker).to_string()));
            let _ = tx.send(frame);
        }
    });
}

async fn delete_connections(State(s): State<Arc<ClashState>>) -> StatusCode {
    for snap in s.connection_tracker.snapshot() {
        s.connection_tracker.remove(&snap.id);
    }
    StatusCode::NO_CONTENT
}

async fn delete_connection(State(s): State<Arc<ClashState>>, Path(id): Path<String>) -> StatusCode {
    s.connection_tracker.remove(&id);
    StatusCode::NO_CONTENT
}

async fn traffic_totals(s: &ClashState) -> (u64, u64) {
    traffic_totals_stats(&s.stats)
}

fn traffic_totals_stats(stats: &crate::stats::StatsManager) -> (u64, u64) {
    stats.snapshot().values().fold((0, 0), |(up, down), value| {
        (up + value.tx_bytes, down + value.rx_bytes)
    })
}

async fn get_traffic(State(s): State<Arc<ClashState>>, ws: MaybeWs) -> Response {
    let Some(ws) = ws.0 else {
        return chunked_json_response(traffic_chunk_stream(s));
    };
    ws.on_upgrade(move |socket| traffic_ws(socket, s))
}

async fn stream_ws_frames(
    mut socket: WebSocket,
    mut frames: tokio::sync::broadcast::Receiver<Arc<Bytes>>,
) {
    loop {
        match frames.recv().await {
            Ok(frame) => {
                if socket
                    .send(Message::Text(
                        std::str::from_utf8(frame.as_ref())
                            .expect("sampler JSON is UTF-8")
                            .into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn traffic_ws(socket: WebSocket, s: Arc<ClashState>) {
    ensure_traffic_sampler(&s);
    stream_ws_frames(socket, s.stream_samplers.traffic.subscribe()).await
}

fn ensure_traffic_sampler(s: &Arc<ClashState>) {
    if s.stream_samplers
        .traffic_started
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    let state = Arc::clone(s);
    let tx = state.stream_samplers.traffic.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous = traffic_totals(&state).await;
        loop {
            tick.tick().await;
            if tx.receiver_count() == 0 {
                continue;
            }
            let current = traffic_totals(&state).await;
            let frame = Arc::new(Bytes::from(
                serde_json::json!({
                    "up": current.0.saturating_sub(previous.0),
                    "down": current.1.saturating_sub(previous.1),
                })
                .to_string(),
            ));
            let _ = tx.send(frame);
            previous = current;
        }
    });
}

fn rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("VmRSS:")?
                    .trim()
                    .strip_suffix(" kB")?
                    .parse::<u64>()
                    .ok()
            })
        })
        .unwrap_or(0)
        * 1024
}

async fn get_memory(State(s): State<Arc<ClashState>>, ws: MaybeWs) -> Response {
    ensure_memory_sampler(&s);
    let Some(ws) = ws.0 else {
        return chunked_json_response(sampler_chunk_stream(s.stream_samplers.memory.subscribe()));
    };
    ws.on_upgrade(move |socket| stream_ws_frames(socket, s.stream_samplers.memory.subscribe()))
}

fn ensure_memory_sampler(s: &Arc<ClashState>) {
    if s.stream_samplers
        .memory_started
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    let tx = s.stream_samplers.memory.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if tx.receiver_count() == 0 {
                continue;
            }
            let frame = Arc::new(Bytes::from(
                serde_json::json!({
                    "inuse": rss_bytes(),
                    "oslimit": 0,
                })
                .to_string(),
            ));
            let _ = tx.send(frame);
        }
    });
}

/// Chunked-HTTP fallback for `/traffic`: the same per-second delta frames
/// as the WS stream, one JSON document per line.
fn traffic_chunk_stream(
    s: Arc<ClashState>,
) -> impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    ensure_traffic_sampler(&s);
    sampler_chunk_stream(s.stream_samplers.traffic.subscribe())
}

fn sampler_chunk_stream(
    receiver: tokio::sync::broadcast::Receiver<Arc<Bytes>>,
) -> impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    futures::stream::unfold(receiver, |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(frame) => {
                    let mut line = Vec::with_capacity(frame.len() + 1);
                    line.extend_from_slice(frame.as_ref());
                    line.push(b'\n');
                    return Some((Ok(Bytes::from(line)), receiver));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

/// Wrap a JSON-lines stream into a chunked `application/json` response.
fn chunked_json_response<S>(stream: S) -> Response
where
    S: futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .expect("chunked stream response")
}

#[derive(Debug, serde::Deserialize)]
struct LogsQuery {
    #[serde(default)]
    level: Option<String>,
}

async fn get_logs(
    State(s): State<Arc<ClashState>>,
    Query(query): Query<LogsQuery>,
    ws: MaybeWs,
) -> Response {
    let level_text = query.level.as_deref().unwrap_or("info");
    let Some(level) = logs::parse_level(level_text) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid log level");
    };
    let subscription = s.log_handle.subscribe(level);
    let Some(ws) = ws.0 else {
        return chunked_json_response(logs_chunk_stream(subscription));
    };
    ws.on_upgrade(move |socket| logs_ws(socket, subscription))
}

/// Stream broadcast log events as `{"type": level, "payload": line}`.
async fn logs_ws(mut socket: WebSocket, mut subscription: logs::LogSubscription) {
    loop {
        match subscription.recv().await {
            Ok(event) => {
                if !subscription.includes(event.level) {
                    continue;
                }
                let msg = serde_json::json!({
                    "type": event.level.as_str().to_lowercase(),
                    "payload": event.payload,
                });
                if socket
                    .send(Message::Text(msg.to_string().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Chunked-HTTP fallback for `/logs`: the same event documents as the WS
/// stream, one JSON object per line.
fn logs_chunk_stream(
    subscription: logs::LogSubscription,
) -> impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    futures::stream::unfold(subscription, |mut subscription| async move {
        loop {
            match subscription.recv().await {
                Ok(event) => {
                    if !subscription.includes(event.level) {
                        continue;
                    }
                    let line = format!(
                        "{}\n",
                        serde_json::json!({
                            "type": event.level.as_str().to_lowercase(),
                            "payload": event.payload,
                        })
                    );
                    return Some((Ok(Bytes::from(line)), subscription));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

/// Query params for `/dns/query`: `?name=<domain>&type=<A|AAAA|...>`.
#[derive(Debug, serde::Deserialize)]
struct DnsQueryParams {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    qtype: Option<String>,
}

/// GET /dns/query — resolve a name through the control plane's DNS
/// forwarder and return a DoH-style JSON document:
/// `{"Status":0,"Question":[...],"Answer":[{"name","type","TTL","data"}]}`.
/// NXDOMAIN maps to Status 3, upstream failures to Status 2 (SERVFAIL);
/// a missing `name` is a 400.
async fn get_dns_query(
    State(s): State<Arc<ClashState>>,
    Query(q): Query<DnsQueryParams>,
) -> Response {
    let Some(name) = q.name.filter(|n| !n.trim().is_empty()) else {
        return error_response(StatusCode::BAD_REQUEST, "missing name parameter");
    };
    let name = name.trim().trim_end_matches('.').to_string();
    let qtype = match q.qtype.as_deref() {
        None => 1, // default: A
        Some(t) => match doh::parse_qtype(t) {
            Some(v) => v,
            None => {
                return error_response(StatusCode::BAD_REQUEST, "invalid type parameter");
            }
        },
    };

    let query = crate::dns::forwarder::build_dns_query(&name, qtype);
    let result = s
        .dns_service
        .resolve(&query, crate::dns::query::IngressProfile::Api)
        .await;
    match result {
        Ok(resp) => Json(doh::response_json(&name, qtype, &resp)).into_response(),
        // Upstream error or negative-cache hit: report SERVFAIL-style.
        Err(e) => {
            tracing::debug!("/dns/query {} type {} failed: {:#}", name, qtype, e);
            Json(serde_json::json!({
                "Status": 2,
                "Question": [{"name": name, "type": qtype}],
                "Answer": [],
            }))
            .into_response()
        }
    }
}

async fn flush_fakeip(State(s): State<Arc<ClashState>>) -> StatusCode {
    if let Some(ref db) = s.cache_db {
        db.flush_prefix("fakeip:");
    }
    StatusCode::NO_CONTENT
}

async fn flush_dns(State(s): State<Arc<ClashState>>) -> StatusCode {
    match s.dns_service.flush_cache().await {
        Ok(true) => {}
        Ok(false) => {
            if let Some(ref db) = s.cache_db {
                db.flush_dns();
            }
        }
        Err(error) => {
            tracing::warn!(%error, "DNS persistence flush command failed");
        }
    }
    StatusCode::NO_CONTENT
}

/// Each group is exposed as a proxy provider holding its members — the
/// minimal provider document dashboards (zashboard/Metacubexd) render. Nested
/// sub-groups appear under their own tag (their representative leaf
/// supplies the delay history), matching the `all` member list.
async fn get_proxy_providers(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    let config = s.config.read().await;
    let gm = s.group_manager.read().clone();
    let mut providers = serde_json::Map::new();

    for group in &config.groups {
        let members = gm.delay_test_members(&group.name);
        // Skip empty groups (e.g. subscription-less groups at startup).
        if members.is_empty() {
            continue;
        }
        let proxies: Vec<serde_json::Value> = members
            .iter()
            .map(|(tag, leaf)| {
                let mut info = build_node_proxy_info(leaf, &s.alive_set);
                info["name"] = serde_json::Value::String(tag.clone());
                info
            })
            .collect();
        providers.insert(
            group.name.clone(),
            serde_json::json!({
                "name": group.name,
                "type": "Proxy",
                "vehicleType": "Compatible",
                "updatedAt": null,
                "proxies": proxies,
            }),
        );
    }

    Json(serde_json::json!({"providers": providers}))
}

async fn get_rule_providers() -> Json<serde_json::Value> {
    Json(serde_json::json!({"providers": []}))
}

#[cfg(test)]
mod sampler_tests {
    use super::*;

    #[tokio::test]
    async fn failed_bind_leaves_connection_tracking_disabled() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tracker = crate::connection_tracker::ConnectionTracker::new();

        assert!(
            bind_listener(occupied.local_addr().unwrap(), &tracker)
                .await
                .is_none()
        );
        assert!(!tracker.is_enabled());
    }

    #[test]
    fn connection_intervals_use_bounded_ceiling_buckets() {
        let cases = [
            (None, 1_000),
            (Some(0), 100),
            (Some(100), 100),
            (Some(101), 200),
            (Some(201), 500),
            (Some(999), 1_000),
            (Some(1_001), 2_000),
            (Some(2_001), 5_000),
            (Some(5_001), 10_000),
            (Some(10_001), 30_000),
            (Some(30_001), 60_000),
            (Some(u64::MAX), 60_000),
        ];
        for (requested, expected_ms) in cases {
            assert_eq!(
                normalize_connection_interval(requested),
                Duration::from_millis(expected_ms)
            );
        }
    }

    #[tokio::test]
    async fn concurrent_subscribers_share_one_sampler_and_idle_task_is_reclaimed() {
        const SUBSCRIBERS: usize = 16;
        let samplers = Arc::new(StreamSamplers::new());
        let tracker = Arc::new(crate::connection_tracker::ConnectionTracker::new());
        let barrier = Arc::new(tokio::sync::Barrier::new(SUBSCRIBERS));
        let interval = Duration::from_millis(10);
        let mut tasks = Vec::with_capacity(SUBSCRIBERS);

        for _ in 0..SUBSCRIBERS {
            let samplers = Arc::clone(&samplers);
            let tracker = Arc::clone(&tracker);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                subscribe_connection_sampler(&samplers, tracker, interval)
            }));
        }

        let mut receivers = Vec::with_capacity(SUBSCRIBERS);
        for task in tasks {
            receivers.push(task.await.unwrap());
        }
        assert_eq!(samplers.connections.len(), 1);
        assert_eq!(
            samplers
                .connections
                .get(&interval)
                .unwrap()
                .receiver_count(),
            SUBSCRIBERS
        );
        for receiver in &mut receivers {
            tokio::time::timeout(Duration::from_millis(100), receiver.recv())
                .await
                .expect("shared sampler frame")
                .unwrap();
        }

        drop(receivers);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(samplers.connections.is_empty());
    }

    #[tokio::test]
    async fn reconnect_after_reclamation_uses_a_new_live_channel() {
        let samplers = Arc::new(StreamSamplers::new());
        let tracker = Arc::new(crate::connection_tracker::ConnectionTracker::new());
        let interval = Duration::from_millis(10);
        let mut first = subscribe_connection_sampler(&samplers, Arc::clone(&tracker), interval);
        let old_tx = samplers.connections.get(&interval).unwrap().clone();
        tokio::time::timeout(Duration::from_millis(100), first.recv())
            .await
            .expect("first sampler frame")
            .unwrap();
        drop(first);

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(samplers.connections.is_empty());

        let mut second = subscribe_connection_sampler(&samplers, tracker, interval);
        let new_tx = samplers.connections.get(&interval).unwrap().clone();
        assert!(!old_tx.same_channel(&new_tx));
        tokio::time::timeout(Duration::from_millis(100), second.recv())
            .await
            .expect("replacement sampler frame")
            .unwrap();
    }
}
