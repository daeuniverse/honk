//! Bounded read-only geodata content inspection over retained asset snapshots.

use std::fs::{File, Metadata};
use std::io::{self, Read as _, Write};
use std::net::IpAddr;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use axum::body::Body;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::super::{
    ApiError, ErrorCode, NativeState, error, invalid_query,
    offline::MAX_ASSET_BYTES,
    parse_query,
    secrets::ListenerSecrets,
    security::{REQUESTS_PER_MINUTE, RequestRate},
    timestamp,
    types::RequestId,
};
use crate::routing::{GeoAssetSnapshot, GeoipScan, GeositeEntry, GeositeScan};

const MAX_PAGE_SIZE: usize = 5000;
const DEFAULT_PAGE_SIZE: usize = 500;
const MAX_RESPONSE_BYTES: usize = 262_144;
const MAX_TOKEN_BYTES: usize = 256;
const MAX_DOMAIN_BYTES: usize = 253;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AssetKind {
    Geosite,
    Geoip,
}

impl AssetKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Geosite => "geosite",
            Self::Geoip => "geoip",
        }
    }
}

enum QueryAction {
    List { filter: Option<String> },
    Show { code: String, attr: Option<String> },
    FindDomain { domain: String },
    FindIp { ip: IpAddr },
}

impl QueryAction {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::List { .. } => "list",
            Self::Show { .. } => "show",
            Self::FindDomain { .. } | Self::FindIp { .. } => "find",
        }
    }
}

struct ParsedQuery {
    kind: AssetKind,
    action: QueryAction,
    limit: usize,
    offset: usize,
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
enum QueryContext {
    List { filter: Option<String> },
    Show { code: String, attr: Option<String> },
    Find { query: String },
}

#[derive(Serialize)]
struct QueryResponse<T> {
    observed_at: String,
    kind: &'static str,
    action: &'static str,
    asset_sha256: String,
    #[serde(flatten)]
    context: QueryContext,
    total: usize,
    offset: usize,
    limit: usize,
    truncated: bool,
    next_offset: Option<usize>,
    items: Vec<T>,
}

#[derive(Serialize)]
struct CategoryItem {
    code: String,
    count: usize,
}

#[derive(Serialize)]
struct GeositeRuleItem {
    #[serde(rename = "type")]
    kind: &'static str,
    value: String,
    attrs: Vec<String>,
}

#[derive(Serialize)]
struct GeositeMatchItem {
    code: String,
    #[serde(rename = "type")]
    kind: &'static str,
    value: String,
    attrs: Vec<String>,
}

#[derive(Serialize)]
struct GeoipCidrItem {
    cidr: String,
}

#[derive(Serialize)]
struct GeoipMatchItem {
    code: String,
    cidr: String,
}

enum ScanFailure {
    CategoryNotFound,
    Unavailable,
}

pub(super) fn capability_from_assets(assets: Option<&[GeoAssetSnapshot]>) -> Value {
    let Some(assets) = assets else {
        return json!({"available": false});
    };
    let kinds: Vec<&'static str> = assets
        .iter()
        .filter(|asset| asset.path.is_some())
        .map(|asset| asset.kind)
        .collect();
    if kinds.is_empty() {
        return json!({"available": false});
    }
    json!({
        "available": true,
        "assets": kinds,
        "actions": ["list", "show", "find"],
        "max_page_size": MAX_PAGE_SIZE,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "per_principal_requests_per_minute": REQUESTS_PER_MINUTE,
        "global_requests_per_minute": REQUESTS_PER_MINUTE,
    })
}

pub(in crate::native_api) async fn serve(
    state: &NativeState,
    rate: &RequestRate,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let parsed = parse_parameters(uri, id)?;
    let (assets, active) = super::capture(state).await?;
    let snapshot = assets
        .into_iter()
        .find(|asset| asset.kind == parsed.kind.as_str() && asset.path.is_some())
        .ok_or_else(super::unsupported)?;
    let secrets = state.observation.configuration.secrets_with(&active);
    drop(active);

    rate.admit(id)?;

    let observed_at = timestamp(SystemTime::now());
    let body = tokio::task::spawn_blocking(move || {
        execute_blocking(parsed, snapshot, secrets, observed_at)
    })
    .await
    .map_err(|_| unavailable(id))?
    .map_err(|failure| match failure {
        ScanFailure::CategoryNotFound => error(
            StatusCode::NOT_FOUND,
            ErrorCode::ResourceNotFound,
            "Geodata category not found.",
            id,
        ),
        ScanFailure::Unavailable => unavailable(id),
    })?;

    Ok((
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(body),
    )
        .into_response())
}

fn parse_parameters(uri: &Uri, id: &RequestId) -> Result<ParsedQuery, ApiError> {
    let params = parse_query(
        uri,
        &[
            "kind", "action", "code", "value", "filter", "attr", "limit", "offset",
        ],
        id,
    )?;
    let kind = match params.get("kind").map(String::as_str).unwrap_or("geosite") {
        "geosite" => AssetKind::Geosite,
        "geoip" => AssetKind::Geoip,
        _ => return Err(invalid_query(id)),
    };
    let limit = match params.get("limit") {
        Some(raw) => parse_decimal_usize(raw)
            .filter(|&n| (1..=MAX_PAGE_SIZE).contains(&n))
            .ok_or_else(|| invalid_query(id))?,
        None => DEFAULT_PAGE_SIZE,
    };
    let offset = match params.get("offset") {
        Some(raw) => parse_decimal_usize(raw)
            .filter(|&n| (n as u64) <= crate::observe::MAX_SAFE_UINT)
            .ok_or_else(|| invalid_query(id))?,
        None => 0,
    };
    let action = match params.get("action").map(String::as_str) {
        Some("list") => {
            if params.contains_key("code")
                || params.contains_key("value")
                || params.contains_key("attr")
            {
                return Err(invalid_query(id));
            }
            let filter = match params.get("filter") {
                Some(raw) if valid_token(raw) => Some(raw.clone()),
                Some(_) => return Err(invalid_query(id)),
                None => None,
            };
            QueryAction::List { filter }
        }
        Some("show") => {
            if params.contains_key("value") || params.contains_key("filter") {
                return Err(invalid_query(id));
            }
            let code = params
                .get("code")
                .filter(|raw| valid_word(raw) && !raw.contains('@'))
                .cloned()
                .ok_or_else(|| invalid_query(id))?;
            let attr = match (kind, params.get("attr")) {
                (AssetKind::Geoip, Some(_)) => return Err(invalid_query(id)),
                (_, Some(raw)) if valid_word(raw) => Some(raw.clone()),
                (_, Some(_)) => return Err(invalid_query(id)),
                (_, None) => None,
            };
            QueryAction::Show { code, attr }
        }
        Some("find") => {
            if params.contains_key("code")
                || params.contains_key("filter")
                || params.contains_key("attr")
            {
                return Err(invalid_query(id));
            }
            let raw = params.get("value").ok_or_else(|| invalid_query(id))?;
            match kind {
                AssetKind::Geosite => {
                    let domain = if raw == "." {
                        "."
                    } else {
                        raw.strip_suffix('.').unwrap_or(raw)
                    };
                    if !(1..=MAX_DOMAIN_BYTES).contains(&domain.len())
                        || domain
                            .bytes()
                            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
                    {
                        return Err(invalid_query(id));
                    }
                    QueryAction::FindDomain {
                        domain: domain.to_owned(),
                    }
                }
                AssetKind::Geoip => {
                    let ip = raw
                        .parse::<IpAddr>()
                        .map_err(|_| invalid_query(id))?
                        .to_canonical();
                    QueryAction::FindIp { ip }
                }
            }
        }
        _ => return Err(invalid_query(id)),
    };
    Ok(ParsedQuery {
        kind,
        action,
        limit,
        offset,
    })
}

fn parse_decimal_usize(raw: &str) -> Option<usize> {
    (!raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()))
        .then(|| raw.parse().ok())
        .flatten()
}

fn valid_token(raw: &str) -> bool {
    (1..=MAX_TOKEN_BYTES).contains(&raw.len()) && !raw.bytes().any(|b| b.is_ascii_control())
}

fn valid_word(raw: &str) -> bool {
    valid_token(raw) && !raw.bytes().any(|b| b.is_ascii_whitespace())
}

fn execute_blocking(
    parsed: ParsedQuery,
    snapshot: GeoAssetSnapshot,
    secrets: ListenerSecrets,
    observed_at: String,
) -> Result<Vec<u8>, ScanFailure> {
    let path = snapshot.path.as_deref().ok_or(ScanFailure::Unavailable)?;
    let kind_name = parsed.kind.as_str();
    let action_name = parsed.action.as_str();

    match parsed.kind {
        AssetKind::Geosite => {
            let scan = load_verified_scan(path, &snapshot, GeositeScan::load)?;
            match parsed.action {
                QueryAction::List { filter } => {
                    let needle = filter.as_deref().map(str::to_lowercase);
                    let mut rows: Vec<(&str, usize)> = scan
                        .categories()
                        .iter()
                        .filter(|cat| {
                            needle
                                .as_deref()
                                .is_none_or(|f| cat.code.to_lowercase().contains(f))
                        })
                        .map(|cat| (cat.code.as_str(), cat.entries.len()))
                        .collect();
                    rows.sort_by_cached_key(|(code, _)| code.to_lowercase());
                    let total = rows.len();
                    let context = QueryContext::List {
                        filter: filter.as_deref().map(|f| mask_str(&secrets, f)),
                    };
                    let items =
                        rows.into_iter()
                            .skip(parsed.offset)
                            .map(|(code, count)| CategoryItem {
                                code: mask_lower(&secrets, code),
                                count,
                            });
                    paginate_to_json(
                        observed_at,
                        kind_name,
                        action_name,
                        snapshot.sha256,
                        context,
                        total,
                        parsed.offset,
                        parsed.limit,
                        items,
                    )
                }
                QueryAction::Show { code, attr } => {
                    let cat = scan.category(&code).ok_or(ScanFailure::CategoryNotFound)?;
                    let matching: Vec<&GeositeEntry> = cat
                        .entries
                        .iter()
                        .filter(|entry| {
                            attr.as_deref().is_none_or(|target| {
                                entry
                                    .attrs
                                    .iter()
                                    .any(|key| key.eq_ignore_ascii_case(target))
                            })
                        })
                        .collect();
                    let total = matching.len();
                    let context = QueryContext::Show {
                        code: mask_lower(&secrets, &cat.code),
                        attr: attr.as_deref().map(|a| mask_str(&secrets, a)),
                    };
                    let items =
                        matching
                            .into_iter()
                            .skip(parsed.offset)
                            .map(|entry| GeositeRuleItem {
                                kind: entry.kind.as_str(),
                                value: mask_str(&secrets, &entry.value),
                                attrs: entry
                                    .attrs
                                    .iter()
                                    .map(|attr| mask_str(&secrets, attr))
                                    .collect(),
                            });
                    paginate_to_json(
                        observed_at,
                        kind_name,
                        action_name,
                        snapshot.sha256,
                        context,
                        total,
                        parsed.offset,
                        parsed.limit,
                        items,
                    )
                }
                QueryAction::FindDomain { domain } => {
                    let mut hits = scan.find(&domain);
                    hits.sort_by_cached_key(|(cat, _)| cat.code.to_lowercase());
                    let total = hits.len();
                    let context = QueryContext::Find {
                        query: mask_str(&secrets, &domain),
                    };
                    let items =
                        hits.into_iter()
                            .skip(parsed.offset)
                            .map(|(cat, entry)| GeositeMatchItem {
                                code: mask_lower(&secrets, &cat.code),
                                kind: entry.kind.as_str(),
                                value: mask_str(&secrets, &entry.value),
                                attrs: entry
                                    .attrs
                                    .iter()
                                    .map(|attr| mask_str(&secrets, attr))
                                    .collect(),
                            });
                    paginate_to_json(
                        observed_at,
                        kind_name,
                        action_name,
                        snapshot.sha256,
                        context,
                        total,
                        parsed.offset,
                        parsed.limit,
                        items,
                    )
                }
                QueryAction::FindIp { .. } => Err(ScanFailure::Unavailable),
            }
        }
        AssetKind::Geoip => {
            let scan = load_verified_scan(path, &snapshot, GeoipScan::load)?;
            match parsed.action {
                QueryAction::List { filter } => {
                    let needle = filter.as_deref().map(str::to_lowercase);
                    let mut rows: Vec<(&str, usize)> = scan
                        .categories()
                        .iter()
                        .filter(|cat| {
                            needle
                                .as_deref()
                                .is_none_or(|f| cat.code.to_lowercase().contains(f))
                        })
                        .map(|cat| (cat.code.as_str(), cat.cidrs.len()))
                        .collect();
                    rows.sort_by_cached_key(|(code, _)| code.to_lowercase());
                    let total = rows.len();
                    let context = QueryContext::List {
                        filter: filter.as_deref().map(|f| mask_str(&secrets, f)),
                    };
                    let items =
                        rows.into_iter()
                            .skip(parsed.offset)
                            .map(|(code, count)| CategoryItem {
                                code: mask_lower(&secrets, code),
                                count,
                            });
                    paginate_to_json(
                        observed_at,
                        kind_name,
                        action_name,
                        snapshot.sha256,
                        context,
                        total,
                        parsed.offset,
                        parsed.limit,
                        items,
                    )
                }
                QueryAction::Show { code, .. } => {
                    let cat = scan.category(&code).ok_or(ScanFailure::CategoryNotFound)?;
                    let total = cat.cidrs.len();
                    let context = QueryContext::Show {
                        code: mask_lower(&secrets, &cat.code),
                        attr: None,
                    };
                    let items = cat
                        .cidrs
                        .iter()
                        .skip(parsed.offset)
                        .map(|cidr| GeoipCidrItem {
                            cidr: cidr.to_string(),
                        });
                    paginate_to_json(
                        observed_at,
                        kind_name,
                        action_name,
                        snapshot.sha256,
                        context,
                        total,
                        parsed.offset,
                        parsed.limit,
                        items,
                    )
                }
                QueryAction::FindIp { ip } => {
                    let mut hits: Vec<(&str, String)> = scan
                        .lookup(ip)
                        .into_iter()
                        .map(|(cat, net)| (cat.code.as_str(), net.to_string()))
                        .collect();
                    hits.sort_by(|a, b| {
                        a.0.to_lowercase()
                            .cmp(&b.0.to_lowercase())
                            .then_with(|| a.1.cmp(&b.1))
                    });
                    let total = hits.len();
                    let context = QueryContext::Find {
                        query: ip.to_string(),
                    };
                    let items =
                        hits.into_iter()
                            .skip(parsed.offset)
                            .map(|(code, cidr)| GeoipMatchItem {
                                code: mask_lower(&secrets, code),
                                cidr,
                            });
                    paginate_to_json(
                        observed_at,
                        kind_name,
                        action_name,
                        snapshot.sha256,
                        context,
                        total,
                        parsed.offset,
                        parsed.limit,
                        items,
                    )
                }
                QueryAction::FindDomain { .. } => Err(ScanFailure::Unavailable),
            }
        }
    }
}

/// Canonicalize startup symlinks, open with `O_NONBLOCK | O_NOFOLLOW` so a
/// post-startup FIFO or symlink swap cannot wedge `spawn_blocking`, and hold
/// one regular-file descriptor across digest verification and `/proc/self/fd`
/// loading.
fn load_verified_scan<T>(
    path: &Path,
    snapshot: &GeoAssetSnapshot,
    load: fn(&Path) -> anyhow::Result<T>,
) -> Result<T, ScanFailure> {
    if snapshot.size_bytes > MAX_ASSET_BYTES as u64 {
        return Err(ScanFailure::Unavailable);
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| ScanFailure::Unavailable)?;
    let descriptor = nix::fcntl::open(
        &canonical,
        nix::fcntl::OFlag::O_RDONLY
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_NONBLOCK
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|_| ScanFailure::Unavailable)?;
    let file = File::from(descriptor);
    let before = file.metadata().map_err(|_| ScanFailure::Unavailable)?;
    if !before.is_file() || before.len() != snapshot.size_bytes {
        return Err(ScanFailure::Unavailable);
    }
    let (digest, total) = stream_digest(&file, snapshot.size_bytes)?;
    if total != snapshot.size_bytes || digest != snapshot.sha256 {
        return Err(ScanFailure::Unavailable);
    }
    let fd_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let scan = load(&fd_path).map_err(|_| ScanFailure::Unavailable)?;
    let after = file.metadata().map_err(|_| ScanFailure::Unavailable)?;
    if !same_version(&before, &after) {
        return Err(ScanFailure::Unavailable);
    }
    Ok(scan)
}

fn stream_digest(file: &File, expected_bytes: u64) -> Result<(String, u64), ScanFailure> {
    let mut reader = file.take(expected_bytes.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                return Ok((
                    crate::configuration::encode_digest(&hasher.finalize()),
                    total,
                ));
            }
            Ok(read) => {
                total = total.saturating_add(read as u64);
                if total > expected_bytes {
                    return Err(ScanFailure::Unavailable);
                }
                hasher.update(&buf[..read]);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ScanFailure::Unavailable),
        }
    }
}

fn same_version(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

/// Mask listener secrets before lowercasing or counting JSON bytes, because
/// `<redacted>` can lengthen an 8-byte secret and case-folding first would miss
/// mixed-case secrets.
fn mask_lower(secrets: &ListenerSecrets, raw: &str) -> String {
    secrets.mask_borrowed(raw).to_lowercase()
}

fn mask_str(secrets: &ListenerSecrets, raw: &str) -> String {
    secrets.mask_borrowed(raw).into_owned()
}

#[allow(clippy::too_many_arguments)]
fn paginate_to_json<T: Serialize>(
    observed_at: String,
    kind: &'static str,
    action: &'static str,
    asset_sha256: String,
    context: QueryContext,
    total: usize,
    offset: usize,
    limit: usize,
    candidates: impl Iterator<Item = T>,
) -> Result<Vec<u8>, ScanFailure> {
    let worst_envelope = QueryResponse::<T> {
        observed_at: observed_at.clone(),
        kind,
        action,
        asset_sha256: asset_sha256.clone(),
        context: context.clone(),
        total,
        offset,
        limit,
        truncated: false,
        next_offset: Some(total.max(offset).max(1_000)),
        items: Vec::new(),
    };
    let envelope_bytes = json_size(&worst_envelope)
        .map_err(|_| ScanFailure::Unavailable)?
        .saturating_add(16);
    let mut remaining = MAX_RESPONSE_BYTES
        .checked_sub(envelope_bytes)
        .ok_or(ScanFailure::Unavailable)?;

    let mut items = Vec::new();
    for item in candidates.take(limit) {
        let item_bytes = json_size(&item).map_err(|_| ScanFailure::Unavailable)?;
        let sep = usize::from(!items.is_empty());
        let needed = sep.saturating_add(item_bytes);
        if needed > remaining {
            if items.is_empty() {
                return Err(ScanFailure::Unavailable);
            }
            break;
        }
        remaining -= needed;
        items.push(item);
    }

    let next = offset.saturating_add(items.len());
    let truncated = next < total;
    let response = QueryResponse {
        observed_at,
        kind,
        action,
        asset_sha256,
        context,
        total,
        offset,
        limit,
        truncated,
        next_offset: truncated.then_some(next),
        items,
    };
    let mut writer = BoundedJson(
        Vec::with_capacity(MAX_RESPONSE_BYTES - remaining),
        MAX_RESPONSE_BYTES,
    );
    serde_json::to_writer(&mut writer, &response).map_err(|_| ScanFailure::Unavailable)?;
    Ok(writer.0)
}

fn json_size(value: &impl Serialize) -> Result<usize, serde_json::Error> {
    struct ByteCounter(usize);
    impl Write for ByteCounter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}

struct BoundedJson(Vec<u8>, usize);

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > self.1 {
            return Err(io::Error::other("geodata query response budget exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn unavailable(id: &RequestId) -> ApiError {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Loaded geodata cannot be inspected right now.",
        id,
    )
    .with_retry_after(1)
}
