//! Geodata download sources kept in the state db, the automatic update
//! schedule, and the outcome of the last update attempt.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use honk_config::experimental::{MAX_GEODATA_URL_BYTES, NativeApiConfig, parse_geodata_url};
use parking_lot::Mutex;
use rusqlite::{OptionalExtension as _, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::native_api::ApiError;
use crate::state::StateDb;

pub(crate) const KINDS: [&str; 2] = ["geosite", "geoip"];
pub(super) const MAX_URLS: usize = 4;
pub(super) const INTERVAL_HOURS: std::ops::RangeInclusive<u64> = 6..=168;
const MAX_JITTER_SECS: u64 = 3600;
const FIRST_BACKOFF: Duration = Duration::from_secs(3600);
/// MetaCubeX full, raw first; jsDelivr serves the same bytes where GitHub is slow.
const DEFAULT_URLS: [[&str; 2]; 2] = [
    [
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat",
        "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
    ],
    [
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat",
        "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
    ],
];

fn index(kind: &str) -> Option<usize> {
    KINDS.iter().position(|known| *known == kind)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutoUpdate {
    pub(crate) enabled: bool,
    pub(crate) interval_hours: u64,
}

impl Default for AutoUpdate {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: 24,
        }
    }
}

/// How geodata requests leave the device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "route", content = "group", rename_all = "lowercase")]
pub(crate) enum Route {
    /// The routing rules decide, as for user traffic and every other download
    /// honk makes itself.
    #[default]
    Routing,
    /// Always through the named group.
    Group(String),
    /// Straight to the host, outside the routing rules.
    Direct,
}

impl Route {
    /// The configuration file's `geodata_download_detour`; `None` when empty,
    /// which leaves the stored route or the routing default in force.
    pub(crate) fn from_detour(detour: &str) -> Option<Self> {
        use crate::download_route::Detour;
        (!detour.is_empty()).then(|| match Detour::parse(detour) {
            Detour::Direct => Self::Direct,
            Detour::Routing => Self::Routing,
            Detour::Group(group) => Self::Group(group.to_owned()),
        })
    }

    /// `{route, group_id}`, the group named by the id `group_id` finds, or null.
    pub(crate) fn json(&self, group_id: impl Fn(&str) -> Option<String>) -> Value {
        let (route, group) = match self {
            Self::Routing => ("routing", None),
            Self::Group(name) => ("group", group_id(name)),
            Self::Direct => ("direct", None),
        };
        json!({"route": route, "group_id": group})
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    /// One list per entry of `KINDS`; an asset without one uses its default.
    #[serde(default)]
    urls: [Option<StoredUrls>; 2],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto_update: Option<AutoUpdate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    download: Option<StoredRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verify_checksum: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRoute {
    route: Route,
    /// The route was last written from the configuration file.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    from_config: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredUrls {
    urls: Vec<String>,
    /// The list was last written from the configuration file.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    from_config: bool,
}

impl Stored {
    fn valid(&self) -> bool {
        self.urls
            .iter()
            .flatten()
            .all(|list| valid_urls(&list.urls))
            && self
                .auto_update
                .is_none_or(|auto| INTERVAL_HOURS.contains(&auto.interval_hours))
            && self
                .download
                .as_ref()
                .is_none_or(|stored| stored.route != Route::Group(String::new()))
    }
}

fn valid_urls(urls: &[String]) -> bool {
    (1..=MAX_URLS).contains(&urls.len())
        && urls.iter().enumerate().all(|(position, url)| {
            url.len() <= MAX_GEODATA_URL_BYTES
                && parse_geodata_url(url).is_some()
                && !urls[..position].contains(url)
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Source {
    Config,
    Override,
    Default,
}

/// The stored URLs and schedule, or the built-in ones where nothing is stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Effective {
    pub(crate) source: Source,
    pub(crate) urls: [Vec<String>; 2],
    pub(crate) auto_update: AutoUpdate,
    pub(crate) download: Route,
    /// Each file has to match the sha256 published beside it, unless none is.
    pub(crate) verify_checksum: bool,
}

impl Effective {
    pub(crate) fn urls(&self, kind: &str) -> &[String] {
        index(kind).map_or(&[], |index| &self.urls[index])
    }

    /// The runtime settings `geodata` object, each URL passed through
    /// `display` and the route's group through `group_id`.
    pub(crate) fn json(
        &self,
        display: impl Fn(&str) -> String,
        group_id: impl Fn(&str) -> Option<String>,
    ) -> Value {
        let list = |urls: &[String]| urls.iter().map(|url| display(url)).collect::<Vec<_>>();
        json!({"source": self.source,
            "geosite": {"urls": list(&self.urls[0])},
            "geoip": {"urls": list(&self.urls[1])},
            "auto_update": self.auto_update,
            "download": self.download.json(group_id),
            "verify_checksum": self.verify_checksum})
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Patch {
    geosite: Option<UrlsPatch>,
    geoip: Option<UrlsPatch>,
    auto_update: Option<AutoUpdatePatch>,
    /// A group route holds the group id until `resolve_group` names the group.
    #[serde(deserialize_with = "route_patch", default)]
    download: Option<Route>,
    verify_checksum: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutePatch {
    route: RouteKind,
    group_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RouteKind {
    Routing,
    Group,
    Direct,
}

/// `group_id` names a group for the group route and is refused otherwise.
fn route_patch<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Route>, D::Error> {
    let patch = RoutePatch::deserialize(deserializer)?;
    let route = match (patch.route, patch.group_id) {
        (RouteKind::Routing, None) => Route::Routing,
        (RouteKind::Direct, None) => Route::Direct,
        (RouteKind::Group, Some(id)) if !id.is_empty() => Route::Group(id),
        _ => {
            return Err(serde::de::Error::custom(
                "group_id belongs to the group route",
            ));
        }
    };
    Ok(Some(route))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UrlsPatch {
    urls: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AutoUpdatePatch {
    enabled: Option<bool>,
    interval_hours: Option<u64>,
}

impl Patch {
    /// `None` for `"geodata": null`, which deletes what is stored.
    pub(crate) fn parse(
        value: Value,
        invalid: impl Fn() -> ApiError,
    ) -> Result<Option<Self>, ApiError> {
        if value.is_null() {
            return Ok(None);
        }
        if contains_null(&value) {
            return Err(invalid());
        }
        let patch: Self = crate::native_api::body::decode_value(value, "geodata", &invalid)?;
        let urls_valid = [&patch.geosite, &patch.geoip]
            .into_iter()
            .flatten()
            .all(|patch| valid_urls(&patch.urls));
        let auto_valid = patch.auto_update.as_ref().is_none_or(|auto| {
            (auto.enabled.is_some() || auto.interval_hours.is_some())
                && auto
                    .interval_hours
                    .is_none_or(|hours| INTERVAL_HOURS.contains(&hours))
        });
        let any = patch.geosite.is_some()
            || patch.geoip.is_some()
            || patch.auto_update.is_some()
            || patch.download.is_some()
            || patch.verify_checksum.is_some();
        if any && urls_valid && auto_valid {
            Ok(Some(patch))
        } else {
            Err(invalid())
        }
    }
}

impl Patch {
    /// Replaces a group route's id with the group `name_of` finds for it;
    /// `false` when it finds none.
    pub(crate) fn resolve_group(&mut self, name_of: impl FnOnce(&str) -> Option<String>) -> bool {
        match &mut self.download {
            Some(Route::Group(group)) => match name_of(group) {
                Some(name) => {
                    *group = name;
                    true
                }
                None => false,
            },
            _ => true,
        }
    }
}

fn contains_null(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(values) => values.iter().any(contains_null),
        Value::Object(object) => object.values().any(contains_null),
        _ => false,
    }
}

/// Where a downloaded file came from, kept while it is the loaded file.
#[derive(Clone, Debug)]
pub(crate) struct Fetched {
    pub(crate) kind: &'static str,
    pub(crate) url: String,
    pub(crate) sha256: String,
    pub(crate) verified: bool,
    /// The route in force for the download.
    pub(crate) route: Route,
    /// The group the request went through, including one the rules chose.
    pub(crate) group: Option<String>,
}

#[derive(Default)]
struct Status {
    last_checked_at: Option<SystemTime>,
    last_updated_at: Option<SystemTime>,
    next_check_at: Option<SystemTime>,
    last_error: Option<String>,
    failures: u32,
    fetched: [Option<Fetched>; 2],
}

pub(crate) struct Sources {
    db: Arc<StateDb>,
    stored: Mutex<Stored>,
    status: Mutex<Status>,
    changed: tokio::sync::Notify,
}

impl Sources {
    /// Reads the stored settings and seeds the configuration file's URLs.
    /// A record that fails its checks is ignored until the next write
    /// replaces it; a state db that cannot be read or written is an error.
    pub(crate) fn open(db: Arc<StateDb>, settings: &NativeApiConfig) -> rusqlite::Result<Self> {
        let record: Option<String> = db
            .strict()
            .query_row(
                "SELECT record FROM geodata_settings WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let stored = record.map_or_else(Stored::default, |record| {
            serde_json::from_str::<Stored>(&record)
                .ok()
                .filter(Stored::valid)
                .unwrap_or_else(|| {
                    tracing::warn!(
                        "stored geodata settings are unusable and ignored; the built-in sources apply"
                    );
                    Stored::default()
                })
        });
        let sources = Self {
            db,
            stored: Mutex::new(stored),
            status: Mutex::new(Status::default()),
            changed: tokio::sync::Notify::new(),
        };
        sources.seed(settings)?;
        sources.reschedule(SystemTime::now());
        Ok(sources)
    }

    pub(crate) fn effective(&self) -> Effective {
        effective(&self.stored.lock())
    }

    /// Stores each URL and the route the configuration file names, over
    /// whatever a patch stored. A value the file does not name is kept when a
    /// patch stored it and deleted when an earlier file wrote it, so its
    /// default applies again.
    fn seed(&self, settings: &NativeApiConfig) -> rusqlite::Result<()> {
        let file = [&settings.geosite_download_url, &settings.geoip_download_url];
        let mut stored = self.stored.lock();
        let mut next = stored.clone();
        for (list, url) in next.urls.iter_mut().zip(file) {
            if !url.is_empty() {
                *list = Some(StoredUrls {
                    urls: vec![url.clone()],
                    from_config: true,
                });
            } else if list.as_ref().is_some_and(|list| list.from_config) {
                *list = None;
            }
        }
        match Route::from_detour(&settings.geodata_download_detour) {
            Some(route) => {
                next.download = Some(StoredRoute {
                    route,
                    from_config: true,
                })
            }
            None if next
                .download
                .as_ref()
                .is_some_and(|route| route.from_config) =>
            {
                next.download = None;
            }
            None => {}
        }
        if next != *stored {
            self.write(&next)?;
            *stored = next;
        }
        Ok(())
    }

    /// Stores a patch, or deletes everything stored for `None`. The schedule
    /// follows a changed `auto_update` at once.
    pub(crate) fn apply(&self, patch: Option<Patch>) -> rusqlite::Result<Effective> {
        let mut stored = self.stored.lock();
        let current = effective(&stored);
        let next = match patch {
            None => Stored::default(),
            Some(patch) => {
                let mut next = stored.clone();
                for (list, patch) in next.urls.iter_mut().zip([patch.geosite, patch.geoip]) {
                    if let Some(patch) = patch {
                        *list = Some(StoredUrls {
                            urls: patch.urls,
                            from_config: false,
                        });
                    }
                }
                if let Some(auto) = patch.auto_update {
                    let mut value = current.auto_update;
                    value.enabled = auto.enabled.unwrap_or(value.enabled);
                    value.interval_hours = auto.interval_hours.unwrap_or(value.interval_hours);
                    next.auto_update = Some(value);
                }
                if let Some(route) = patch.download {
                    next.download = Some(StoredRoute {
                        route,
                        from_config: false,
                    });
                }
                if let Some(verify) = patch.verify_checksum {
                    next.verify_checksum = Some(verify);
                }
                next
            }
        };
        self.write(&next)?;
        let schedule_changed = next.auto_update != stored.auto_update;
        *stored = next;
        let effective = effective(&stored);
        drop(stored);
        if schedule_changed {
            self.reschedule(SystemTime::now());
        }
        Ok(effective)
    }

    fn write(&self, stored: &Stored) -> rusqlite::Result<()> {
        let mut connection = self.db.strict();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if *stored == Stored::default() {
            transaction.execute("DELETE FROM geodata_settings", [])?;
        } else {
            let record = serde_json::to_string(stored).expect("stored settings serialize");
            transaction.execute(
                "INSERT INTO geodata_settings (id, record) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET record = excluded.record",
                [&record],
            )?;
        }
        transaction.commit()
    }

    pub(crate) fn next_check_at(&self) -> Option<SystemTime> {
        self.status.lock().next_check_at
    }

    /// Resolves once the schedule may have moved.
    pub(crate) fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.changed.notified()
    }

    /// Before this process has checked, the wait counts from `now`, so a
    /// startup never downloads at once, whatever the loaded files' age.
    fn reschedule(&self, now: SystemTime) {
        let stored = self.stored.lock();
        let auto = effective(&stored).auto_update;
        let mut status = self.status.lock();
        status.next_check_at = auto.enabled.then(|| {
            status.last_checked_at.unwrap_or(now) + wait(auto, status.failures) + jitter()
        });
        drop(status);
        drop(stored);
        self.changed.notify_one();
    }

    /// Records a finished attempt, manual or automatic; `replaced` when it
    /// changed a loaded file.
    pub(crate) fn record(&self, outcome: Result<(Vec<Fetched>, bool), String>) {
        let now = SystemTime::now();
        {
            let mut status = self.status.lock();
            status.last_checked_at = Some(now);
            match outcome {
                Ok((fetched, replaced)) => {
                    status.failures = 0;
                    status.last_error = None;
                    if replaced {
                        status.last_updated_at = Some(now);
                    }
                    for fetched in fetched {
                        if let Some(index) = index(fetched.kind) {
                            status.fetched[index] = Some(fetched);
                        }
                    }
                }
                Err(code) => {
                    status.failures = status.failures.saturating_add(1);
                    status.last_error = Some(code);
                }
            }
        }
        self.reschedule(now);
    }

    /// Moves a due check an hour on while an update that will record its
    /// own outcome holds the operation.
    pub(crate) fn postpone(&self) {
        let mut status = self.status.lock();
        if status.next_check_at.is_some() {
            status.next_check_at = Some(SystemTime::now() + FIRST_BACKOFF + jitter());
        }
    }

    /// Where the loaded `kind` file came from, when this process downloaded it.
    pub(crate) fn fetched(&self, kind: &str, sha256: &str) -> Option<Fetched> {
        let status = self.status.lock();
        status.fetched[index(kind)?]
            .as_ref()
            .filter(|fetched| fetched.sha256 == sha256)
            .cloned()
    }

    /// `last_checked_at`, `last_updated_at`, `next_check_at` and `last_error`.
    pub(crate) fn status_json(&self, timestamp: impl Fn(SystemTime) -> String) -> Value {
        let status = self.status.lock();
        json!({
            "last_checked_at": status.last_checked_at.map(&timestamp),
            "last_updated_at": status.last_updated_at.map(&timestamp),
            "next_check_at": status.next_check_at.map(&timestamp),
            "last_error": status.last_error.as_ref().map(|code| json!({
                "code": code,
                "message": "Geodata update did not complete successfully",
                "details": null,
            })),
        })
    }
}

/// `source` is `config` only while every stored list came from the file; the
/// route does not affect it.
fn effective(stored: &Stored) -> Effective {
    let mut lists = stored.urls.iter().flatten().peekable();
    let source = if lists.peek().is_none() {
        Source::Default
    } else if lists.all(|list| list.from_config) {
        Source::Config
    } else {
        Source::Override
    };
    Effective {
        source,
        urls: std::array::from_fn(|index| {
            stored.urls[index].as_ref().map_or_else(
                || DEFAULT_URLS[index].map(str::to_owned).to_vec(),
                |list| list.urls.clone(),
            )
        }),
        auto_update: stored.auto_update.unwrap_or_default(),
        download: stored
            .download
            .as_ref()
            .map_or_else(Route::default, |stored| stored.route.clone()),
        verify_checksum: stored.verify_checksum.unwrap_or(true),
    }
}

/// The wait before the next automatic attempt, without its random delay:
/// the interval, or after `failures` consecutive failures a backoff that
/// starts at one hour, doubles, and never exceeds the interval.
fn wait(auto: AutoUpdate, failures: u32) -> Duration {
    let interval = Duration::from_secs(auto.interval_hours * 3600);
    if failures == 0 {
        return interval;
    }
    FIRST_BACKOFF
        .saturating_mul(1 << (failures - 1).min(16))
        .min(interval)
}

/// Up to an hour, so many devices on the same schedule do not download at once.
fn jitter() -> Duration {
    Duration::from_secs(rand::random_range(0..=MAX_JITTER_SECS))
}

#[cfg(test)]
mod tests;
