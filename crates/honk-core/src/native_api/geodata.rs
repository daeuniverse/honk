use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::extract::Request;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use honk_config::experimental::{NativeApiConfig, parse_geodata_url};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::time::Instant;

use super::operations::{OperationKind, Reservation};
use super::{ApiError, ErrorCode, NativeState, config, parse_query, timestamp, types::RequestId};
use crate::download_route::{self, Detour, Failed, Outbounds};
use crate::marked_http::Deadline;
use crate::routing::{GeoAssetSnapshot, GeoRequirements};

mod sources;
#[cfg(test)]
mod tests;

pub(crate) use sources::{Fetched, Patch as SourcesPatch, Route, Sources};

/// How long a file download may wait for any progress: the setup up to the
/// answer's headers, and then each wait for more of the body.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a file download may take in all, so a trickle cannot hold the
/// update forever.
pub(crate) const DOWNLOAD_LIMIT: Duration = Duration::from_secs(600);
/// The checksum request gets its own deadline instead of whatever a slow file
/// download left. It covers the whole request: a fresh route decision,
/// resolution, the tunnel, TLS and a body of at most `MAX_CHECKSUM_BYTES`.
const CHECKSUM_TIMEOUT: Duration = Duration::from_secs(10);
const UPDATE_PATH: &str = "/api/v1/geodata/update";
const MAX_CHECKSUM_BYTES: usize = 1024;

#[derive(Serialize)]
pub(crate) struct GeoData {
    observed_at: String,
    assets: Vec<GeoAsset>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    status: Option<Value>,
}

#[derive(Serialize)]
struct GeoAsset {
    kind: &'static str,
    sha256: String,
    size_bytes: String,
    modified_at: Option<String>,
    source_redacted: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    origin: Option<Origin>,
}

#[derive(Serialize)]
struct Origin {
    fetched_url_redacted: Option<String>,
    verified: bool,
    download_route: Option<Value>,
}

impl std::fmt::Debug for GeoData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeoData")
            .field("observed_at", &self.observed_at)
            .field("asset_count", &self.assets.len())
            .finish_non_exhaustive()
    }
}

pub(crate) struct GeoUpdatePlan {
    pub(crate) traffic_router: Arc<tokio::sync::RwLock<crate::routing::Router>>,
    pub(crate) dns: crate::dns::DnsService,
    pub(crate) assets: Vec<GeoAssetSnapshot>,
    pub(crate) revision: String,
    /// Each asset's URLs in fallback order, resolved when the update was queued.
    pub(crate) urls: Vec<Vec<String>>,
    /// The route every request takes, resolved when the update was queued.
    pub(crate) route: Route,
    /// Whether each file has to match its published sha256, resolved when the
    /// update was queued.
    pub(crate) verify_checksum: bool,
    pub(crate) group_manager: honk_outbound::group::SharedGroupManager,
    pub(crate) proxy_registry: Arc<crate::proxy::ProxyRegistry>,
    pub(crate) runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    pub(crate) catalog: Arc<crate::observe::catalog::Catalog>,
    pub(crate) sources: Option<Arc<Sources>>,
}

/// How an update's requests reach their URLs.
pub(crate) struct Egress<'a> {
    pub(crate) bootstrap: &'a str,
    pub(crate) route: &'a Route,
    pub(crate) outbounds: Outbounds<'a>,
}

/// The loaded assets and the configuration published with them.
pub(crate) async fn capture(
    state: &NativeState,
) -> Result<(Vec<GeoAssetSnapshot>, Arc<honk_config::Config>), ApiError> {
    capture_assets(&state.traffic_router, &state.config, &state.dns).await
}

pub(crate) async fn capture_assets(
    traffic_router: &tokio::sync::RwLock<crate::routing::Router>,
    config: &tokio::sync::RwLock<Arc<honk_config::Config>>,
    dns: &crate::dns::DnsService,
) -> Result<(Vec<GeoAssetSnapshot>, Arc<honk_config::Config>), ApiError> {
    // Reload publishes under the same router-before-config lock order.
    let router = traffic_router.read().await;
    let config = config.read().await;
    let mut assets = router.geo_assets().to_vec();
    for asset in dns.geo_assets() {
        if let Some(previous) = assets
            .iter_mut()
            .find(|previous| previous.kind == asset.kind)
        {
            if previous.path != asset.path
                || previous.sha256 != asset.sha256
                || previous.size_bytes != asset.size_bytes
            {
                return Err(unsupported());
            }
            if previous.modified_at != asset.modified_at {
                previous.modified_at = None;
            }
        } else {
            assets.push(asset);
        }
    }
    assets.sort_by_key(|asset| if asset.kind == "geosite" { 0 } else { 1 });
    Ok((assets, Arc::clone(&config)))
}

/// The configuration file's download URL for `kind`, empty when it names none.
pub(crate) fn file_url<'a>(settings: &'a NativeApiConfig, kind: &str) -> &'a str {
    match kind {
        "geosite" => &settings.geosite_download_url,
        "geoip" => &settings.geoip_download_url,
        _ => "",
    }
}

/// The URLs for `kind`, in fallback order: the stored or built-in sources when
/// they are configurable, otherwise the configuration file's one URL.
pub(crate) fn urls(
    settings: &NativeApiConfig,
    sources: Option<&Sources>,
    kind: &str,
) -> Vec<String> {
    if let Some(sources) = sources {
        return sources.effective().urls(kind).to_vec();
    }
    let url = file_url(settings, kind);
    if url.is_empty() {
        Vec::new()
    } else {
        vec![url.to_owned()]
    }
}

/// The route in force: the stored one when sources are configurable,
/// otherwise the configuration file's, and routing when it names none.
fn route(settings: &NativeApiConfig, sources: Option<&Sources>) -> Route {
    match sources {
        Some(sources) => sources.effective().download,
        None => Route::from_detour(&settings.geodata_download_detour).unwrap_or_default(),
    }
}

/// A URL as `source_redacted` and `fetched_url_redacted` show it, listener
/// secrets masked; None when it cannot be shown safely.
pub(crate) fn redact(url: &str, secrets: &config::ListenerSecrets) -> Option<String> {
    display_url(url, |text| secrets.contains(text)).map(|url| secrets.mask(&url).0)
}

/// The URL without query and fragment, and with every path segment that may
/// hold a credential replaced. Segments are also checked decoded, because the
/// parser percent-encodes characters a listener secret may contain. A URL with
/// userinfo does not parse.
fn display_url(url: &str, secret: impl Fn(&str) -> bool) -> Option<String> {
    let mut parsed = parse_geodata_url(url)?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    let mut previous = "";
    let path = parsed
        .path()
        .split('/')
        .map(|segment| {
            let hidden = !segment.is_empty()
                && CREDENTIAL_NAMES
                    .iter()
                    .any(|name| previous.eq_ignore_ascii_case(name))
                || segment.contains([':', '='])
                || looks_like_token(segment)
                || secret(&percent_encoding::percent_decode_str(segment).decode_utf8_lossy());
            previous = segment;
            if hidden { "[redacted]" } else { segment }
        })
        .collect::<Vec<_>>()
        .join("/");
    parsed.set_path(&path);
    Some(parsed.into())
}

const CREDENTIAL_NAMES: [&str; 15] = [
    "access_key",
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "auth_token",
    "client_secret",
    "credential",
    "key",
    "password",
    "private_token",
    "secret",
    "sig",
    "signature",
    "token",
];

/// Random tokens mix cases and digits, or run long without separators; UUIDs
/// and 32-digit hex are subscription tokens. Git commit hashes (40-digit
/// lower-case hex) and dash-separated release tags stay.
fn looks_like_token(segment: &str) -> bool {
    let hex = |part: &str| part.bytes().all(|byte| byte.is_ascii_hexdigit());
    let uuid =
        segment.split('-').map(str::len).eq([8, 4, 4, 4, 12]) && hex(&segment.replace('-', ""));
    if uuid || segment.len() == 32 && hex(segment) {
        return true;
    }
    let has = |class: fn(&u8) -> bool| segment.bytes().any(|byte| class(&byte));
    let url_safe = segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    let mixed =
        has(u8::is_ascii_uppercase) && has(u8::is_ascii_lowercase) && has(u8::is_ascii_digit);
    let lower_hex = segment
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    url_safe
        && (segment.len() >= 16 && mixed
            || segment.len() >= 32 && !segment.contains('-') && !lower_hex)
}

pub(crate) fn project(
    assets: Vec<GeoAssetSnapshot>,
    geodata: Option<&Sources>,
    active: &honk_config::Config,
    sources: &config::ConfigService,
    group_id: impl Fn(&str) -> Option<String>,
) -> GeoData {
    let secrets = sources.secrets_with(active);
    let status = geodata.map(|geodata| {
        let requirements = GeoRequirements::for_traffic(&active.routing.rules).union(
            &crate::dns::routing::DnsRouter::geo_requirements(&active.dns),
        );
        let mut status = geodata.status_json(timestamp);
        status["required_codes"] = assets
            .iter()
            .map(|asset| (asset.kind.to_owned(), json!(requirements.codes(asset.kind))))
            .collect::<serde_json::Map<_, _>>()
            .into();
        status
    });
    GeoData {
        observed_at: timestamp(SystemTime::now()),
        assets: assets
            .into_iter()
            .map(|asset| {
                let source_redacted = urls(&active.experimental.native_api, geodata, asset.kind)
                    .first()
                    .and_then(|url| redact(url, &secrets));
                let origin = geodata.map(|geodata| {
                    let fetched = geodata.fetched(asset.kind, &asset.sha256);
                    Origin {
                        verified: fetched.as_ref().is_some_and(|fetched| fetched.verified),
                        download_route: fetched.as_ref().map(|fetched| {
                            let mut route = fetched.route.json(&group_id);
                            route["group_id"] = json!(fetched.group.as_deref().and_then(&group_id));
                            route
                        }),
                        fetched_url_redacted: fetched
                            .and_then(|fetched| redact(&fetched.url, &secrets)),
                    }
                });
                GeoAsset {
                    kind: asset.kind,
                    sha256: asset.sha256,
                    size_bytes: asset.size_bytes.to_string(),
                    modified_at: asset.modified_at.map(timestamp),
                    source_redacted,
                    origin,
                }
            })
            .collect(),
        status,
    }
}

/// The API id of the group named `name`, while it exists.
pub(crate) fn group_id(catalog: &crate::observe::catalog::Catalog, name: &str) -> Option<String> {
    catalog.snapshot().groups.get(name).cloned()
}

fn updatable(state: &NativeState, settings: &NativeApiConfig, assets: &[GeoAssetSnapshot]) -> bool {
    state.observation.configuration.writable()
        && !assets.is_empty()
        && assets.iter().all(|asset| {
            asset.path.is_some() && !urls(settings, state.geodata.as_deref(), asset.kind).is_empty()
        })
}

pub(super) async fn capability(state: &NativeState) -> Value {
    match capture(state).await {
        Ok((assets, active)) => {
            let can_update = updatable(state, &active.experimental.native_api, &assets);
            let mut value = json!({"available": true, "can_update": can_update,
                "assets": assets.iter().map(|asset| asset.kind).collect::<Vec<_>>(),
                "checksum": "sha256sum"});
            if state.geodata.as_ref().is_some() {
                value["configurable_sources"] = json!(true);
                value["max_urls"] = json!(sources::MAX_URLS);
                value["interval_hours"] = json!({"min": sources::INTERVAL_HOURS.start(),
                    "max": sources::INTERVAL_HOURS.end(),
                    "default": sources::AutoUpdate::default().interval_hours});
                // The file is read at startup only; patches live in the state db.
                value["lifecycle"] = json!({"file_values": "start", "overrides_persist": true});
            }
            value
        }
        Err(_) => json!({"available": false}),
    }
}

pub(super) async fn get(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let (assets, active) = capture(state).await?;
    Ok(axum::Json(project(
        assets,
        state.geodata.as_deref(),
        &active,
        &state.observation.configuration,
        |name| group_id(&state.observation.core.catalog, name),
    ))
    .into_response())
}

pub(super) async fn update(
    state: &Arc<NativeState>,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let key = config::request_header(&request, "idempotency-key")?.map(str::to_owned);
    let body = axum::body::to_bytes(request.into_body(), 0)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidRequest,
                "Geodata update takes no request body.",
                None,
            )
        })?;
    let reservation = state.observation.operations.reserve(
        state.principal(),
        "POST",
        UPDATE_PATH,
        key.as_deref(),
        &body,
        OperationKind::GeodataUpdate,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        queue(state, reservation).await;
    }
    Ok(admission.await?.into_response())
}

/// Hands a fresh reservation to the coordinator, or rejects it with the
/// reason no update can run.
async fn queue(state: &Arc<NativeState>, reservation: Reservation) -> bool {
    let prepared = async {
        let (assets, active) = capture(state).await?;
        let settings = &active.experimental.native_api;
        if !updatable(state, settings, &assets) {
            return Err(unsupported());
        }
        let revision = state
            .observation
            .configuration
            .sources
            .revision()
            .ok_or_else(unsupported)?;
        let sources = state.geodata.clone();
        Ok::<_, ApiError>(GeoUpdatePlan {
            traffic_router: Arc::clone(&state.traffic_router),
            dns: state.dns.clone(),
            urls: assets
                .iter()
                .map(|asset| urls(settings, sources.as_deref(), asset.kind))
                .collect(),
            route: route(settings, sources.as_deref()),
            verify_checksum: sources
                .as_deref()
                .is_none_or(|sources| sources.effective().verify_checksum),
            group_manager: Arc::clone(&state.group_manager),
            proxy_registry: Arc::clone(&state.proxy_registry),
            runtime_registry: Arc::clone(&state.runtime_registry),
            catalog: Arc::clone(&state.observation.core.catalog),
            assets,
            revision,
            sources,
        })
    }
    .await;
    match prepared {
        Ok(plan) => state
            .observation
            .configuration
            .queue_geodata(plan, reservation)
            .is_ok(),
        Err(error) => {
            state.observation.operations.reject(&reservation.id, error);
            false
        }
    }
}

/// Runs `geodata_update` when the schedule says so. A manual update in
/// progress holds the operation; its outcome moves the schedule instead.
pub(super) async fn schedule(state: Arc<NativeState>, mut stop: watch::Receiver<bool>) {
    let Some(sources) = state.geodata.clone() else {
        let _ = stop.wait_for(|stopped| *stopped).await;
        return;
    };
    loop {
        let changed = sources.changed();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let due = sources.next_check_at().map(|at| {
            tokio::time::Instant::now() + at.duration_since(SystemTime::now()).unwrap_or_default()
        });
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = &mut changed => {}
            _ = tokio::time::sleep_until(due.unwrap_or_else(tokio::time::Instant::now)), if due.is_some() => {
                match state.observation.operations.reserve(
                    state.principal(),
                    "POST",
                    UPDATE_PATH,
                    None,
                    &[],
                    OperationKind::GeodataUpdate,
                ) {
                    Ok(reservation) => {
                        if queue(&state, reservation).await {
                            sources.postpone();
                        } else {
                            sources.record(Err("update_unavailable".into()));
                        }
                    }
                    Err(error) => {
                        if error.into_response().status() == StatusCode::CONFLICT {
                            sources.postpone();
                        } else {
                            sources.record(Err("update_unavailable".into()));
                        }
                    }
                }
            }
        }
    }
}

fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "Loaded geodata is unavailable for this operation.",
        None,
    )
}

/// Why a URL failed: the stage code, and the status of a rejected HTTP reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Failure {
    pub(crate) code: &'static str,
    pub(crate) status: Option<u16>,
}

impl From<&'static str> for Failure {
    fn from(code: &'static str) -> Self {
        Self { code, status: None }
    }
}

/// Downloads `kind` from the first URL that yields a usable file. A URL is
/// skipped on any download failure, and when fetching the sha256 published
/// beside it fails with anything but a 404 or the digest does not match; the
/// error of the last URL tried is returned. The file fails when it makes no
/// progress for `IDLE_TIMEOUT` or takes longer than `DOWNLOAD_LIMIT`, and its
/// checksum has a separate `CHECKSUM_TIMEOUT` that starts after the file
/// arrives. Every request takes the route in
/// `egress`; one it cannot carry fails like a connection and never goes
/// direct instead. Without `verify_checksum`
/// no checksum is requested and every downloaded file is accepted unverified.
pub(crate) async fn fetch(
    kind: &'static str,
    urls: &[String],
    egress: &Egress<'_>,
    max_bytes: usize,
    verify_checksum: bool,
) -> Result<(Arc<[u8]>, Fetched), Failure> {
    let mut last = Failure::from("invalid_source");
    for url in urls {
        let started = Instant::now();
        let deadline = Deadline {
            headers: started + IDLE_TIMEOUT,
            idle: Some((IDLE_TIMEOUT, started + DOWNLOAD_LIMIT)),
        };
        let (bytes, group) = match download(url, egress, deadline, max_bytes).await {
            Ok(downloaded) => downloaded,
            Err(error) => {
                last = error;
                continue;
            }
        };
        let sha256 = crate::configuration::digest(&bytes);
        let verified = if verify_checksum {
            let Some(mut checksum) = parse_geodata_url(url) else {
                last = "invalid_source".into();
                continue;
            };
            checksum.set_path(&format!("{}.sha256sum", checksum.path()));
            let published = download(
                checksum.as_str(),
                egress,
                (Instant::now() + CHECKSUM_TIMEOUT).into(),
                MAX_CHECKSUM_BYTES,
            )
            .await;
            match published {
                Ok((published, _)) => {
                    let matches = std::str::from_utf8(&published)
                        .ok()
                        .and_then(|text| text.split_whitespace().next())
                        .is_some_and(|expected| expected.eq_ignore_ascii_case(&sha256));
                    if !matches {
                        last = "checksum_mismatch".into();
                        continue;
                    }
                    true
                }
                Err(Failure {
                    code: "http_not_found",
                    ..
                }) => false,
                Err(error) => {
                    last = Failure {
                        code: "checksum_unavailable",
                        status: error.status,
                    };
                    continue;
                }
            }
        } else {
            false
        };
        return Ok((
            bytes,
            Fetched {
                kind,
                url: url.clone(),
                sha256,
                verified,
                route: egress.route.clone(),
                group,
            },
        ));
    }
    Err(last)
}

const DETOUR_SETTING: &str = "geodata.download";
const PURPOSE: &str = "geodata download";

/// Fetches `url` through the route, with the group it went through.
async fn download(
    url: &str,
    egress: &Egress<'_>,
    deadline: Deadline,
    max_bytes: usize,
) -> Result<(Arc<[u8]>, Option<String>), Failure> {
    let routed = match egress.route {
        Route::Direct => None,
        Route::Routing => Some((egress.outbounds, Detour::Routing)),
        Route::Group(group) => Some((egress.outbounds, Detour::Group(group))),
    };
    exchange(url, egress.bootstrap, routed, deadline, max_bytes).await
}

/// Fetches `url` straight from its host, resolved with the bootstrap
/// resolver, over the bypass mark.
#[cfg(test)]
pub(crate) async fn download_direct(
    url: &str,
    bootstrap: &str,
    deadline: Deadline,
    max_bytes: usize,
) -> Result<Arc<[u8]>, Failure> {
    exchange(url, bootstrap, None, deadline, max_bytes)
        .await
        .map(|(bytes, _)| bytes)
}

/// One GET that only a 200 answers, through `routed` or straight to the
/// host; another status is kept for the failure.
async fn exchange(
    url: &str,
    bootstrap: &str,
    routed: Option<(Outbounds<'_>, Detour<'_>)>,
    deadline: Deadline,
    max_bytes: usize,
) -> Result<(Arc<[u8]>, Option<String>), Failure> {
    let url = parse_geodata_url(url).ok_or("invalid_source")?;
    let headers = http::HeaderMap::new();
    let request = download_route::Request {
        url: &url,
        headers: &headers,
        wants_body: |status, _| status == StatusCode::OK,
        deadline,
        max_bytes,
        bootstrap: Some(bootstrap),
    };
    let (reply, group) = match routed {
        None => (download_route::fetch_direct(&request).await?, None),
        Some((outbounds, detour)) => outbounds
            .fetch(detour, DETOUR_SETTING, PURPOSE, &request)
            .await
            .map_err(|failed| match failed {
                Failed::Route(_) => "group_unavailable",
                Failed::Stage(stage) => stage,
            })?,
    };
    match reply.status {
        StatusCode::OK => Ok((reply.body, group)),
        status => Err(Failure {
            code: match status {
                StatusCode::NOT_FOUND => "http_not_found",
                _ => "http_status_rejected",
            },
            status: Some(status.as_u16()),
        }),
    }
}
