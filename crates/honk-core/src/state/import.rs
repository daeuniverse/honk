//! One-time import of state that older releases kept outside the state db.
//!
//! Each source is copied in one strict transaction that also records it in
//! `legacy_import`, so it is never copied twice; the source is removed only
//! after that, with the instance lock held.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, params};

use super::StateDb;

const DELAY_MAX_AGE_SECS: u64 = 24 * 3600;

/// A `cache.db` from before the state db, as `cache_file.path` and
/// `cache_file.cache_id` located it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyCache {
    pub path: PathBuf,
    pub cache_id: String,
}

impl LegacyCache {
    /// The resolver older releases used: an absolute path is literal; a
    /// relative one prefers `data_dir`, then `/var/share/honk`, then
    /// `legacy_config_dir`.
    pub fn locate(
        path: Option<&str>,
        cache_id: Option<&str>,
        legacy_config_dir: Option<&Path>,
    ) -> Self {
        let configured = Path::new(path.filter(|path| !path.is_empty()).unwrap_or("cache.db"));
        let legacy = (!configured.is_absolute()).then(|| {
            legacy_config_dir.map_or_else(|| configured.to_path_buf(), |dir| dir.join(configured))
        });
        Self {
            path: honk_config::paths::resolve_artifact_path_with_legacy(
                configured,
                legacy.as_deref(),
            ),
            cache_id: cache_id.unwrap_or_default().to_owned(),
        }
    }
}

/// The Selector groups and nodes of the running configuration; rows for any
/// other group or node are not imported, so the import stays within what the
/// maintenance tick would keep.
#[derive(Debug, Clone, Default)]
pub struct ImportScope {
    pub selector_groups: std::collections::HashSet<String>,
    pub nodes: std::collections::HashSet<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn done_at() -> i64 {
    i64::try_from(now_unix()).unwrap_or(i64::MAX)
}

/// Imports `legacy` and removes it; call with the instance lock held.
///
/// Keys under this instance's `cache_id` prefix are copied: per-network
/// Selector choices, Clash mode and GLOBAL, and delay samples newer than 24 h.
/// Name-only Selector rows, DNS answers and FakeIP rows are not read. Rows
/// already in the state db win. With a non-empty `cache_id` another instance
/// may share the file, so it stays. A file that is not a private regular file,
/// or that cannot be read as a `cache.db`, is left alone and not recorded.
pub fn import_cache_db(state: &StateDb, legacy: &LegacyCache, scope: &ImportScope) {
    let Some(file) = LegacyFile::open(&legacy.path) else {
        return;
    };
    let source = source_key(&file.path, &legacy.cache_id);
    match copy_cache_db(state, &file, &legacy.cache_id, &source, scope) {
        Ok(false) => {}
        Ok(true) if !legacy.cache_id.is_empty() => tracing::info!(
            path = %file.path.display(),
            "imported this instance's cache_id from the legacy cache.db; the file is kept because another instance may use it"
        ),
        Ok(true) => tracing::info!(path = %file.path.display(), "imported the legacy cache.db"),
        Err(error) => {
            tracing::warn!(%error, path = %file.path.display(), "legacy cache.db not imported; left in place");
            return;
        }
    }
    if legacy.cache_id.is_empty() {
        remove_cache_db(&file.path);
    }
}

#[derive(Debug, thiserror::Error)]
enum ImportError {
    #[error("the file has no kv table")]
    NotCacheDb,
    #[error("the opened file changed")]
    Replaced,
    #[error("the copy would pass the state db's cache page budget")]
    OverBudget,
    #[error("SQLite result code {0}")]
    Sqlite(i32),
}

impl From<rusqlite::Error> for ImportError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error.sqlite_error().map_or(-1, |error| error.extended_code))
    }
}

/// The legacy file, opened without following a final symlink and accepted only
/// as a regular file owned by the euid that no other user can write, as the
/// subscription store checked its files.
struct LegacyFile {
    /// The canonical directory joined with the configured file name.
    path: PathBuf,
    identity: (u64, u64),
}

impl LegacyFile {
    fn open(configured: &Path) -> Option<Self> {
        use std::os::unix::fs::MetadataExt as _;

        let directory = match std::fs::canonicalize(directory_of(configured)) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => {
                tracing::warn!(%error, path = %configured.display(), "legacy cache.db cannot be located; left in place");
                return None;
            }
        };
        let path = directory.join(configured.file_name()?);
        let file = match nix::fcntl::open(
            &path,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_NONBLOCK
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        ) {
            Ok(fd) => std::fs::File::from(fd),
            Err(nix::errno::Errno::ENOENT) => return None,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "legacy cache.db cannot be opened; left in place");
                return None;
            }
        };
        let metadata = file.metadata().ok()?;
        if !metadata.is_file()
            || metadata.uid() != super::effective_uid()
            || metadata.mode() & 0o022 != 0
        {
            tracing::warn!(
                path = %path.display(),
                "legacy cache.db is not a private regular file; left in place"
            );
            return None;
        }
        Some(Self {
            path,
            identity: (metadata.dev(), metadata.ino()),
        })
    }

    fn connect(&self) -> Result<Connection, ImportError> {
        use std::os::unix::fs::MetadataExt as _;

        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let opened = std::fs::symlink_metadata(&self.path).map_err(|_| ImportError::Replaced)?;
        if (opened.dev(), opened.ino()) != self.identity {
            return Err(ImportError::Replaced);
        }
        connection.busy_timeout(std::time::Duration::from_millis(2000))?;
        Ok(connection)
    }
}

/// The directory `configured` is in; a bare file name, as `-c config.dae`
/// resolves `cache.db`, is in the current directory.
fn directory_of(configured: &Path) -> &Path {
    match configured.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// The `legacy_import` key: the canonical path and the `cache_id` whose rows
/// were taken, unambiguous for any `cache_id`.
fn source_key(canonical: &Path, cache_id: &str) -> String {
    format!(
        "cache.db:{}:{cache_id}{}",
        cache_id.len(),
        canonical.display()
    )
}

/// `Ok(true)` when this call copied the file; `Ok(false)` when an earlier
/// start already had. Any read error rolls the copy back and records nothing.
fn copy_cache_db(
    state: &StateDb,
    file: &LegacyFile,
    cache_id: &str,
    source: &str,
    scope: &ImportScope,
) -> Result<bool, ImportError> {
    let mut strict = state.strict();
    let transaction = strict.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if transaction
        .query_row(
            "SELECT 1 FROM legacy_import WHERE source = ?1",
            [source],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Ok(false);
    }
    let legacy = file.connect()?;
    let check: String = legacy.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if check != "ok" {
        return Err(ImportError::Sqlite(rusqlite::ffi::SQLITE_CORRUPT));
    }
    let tables: i64 = legacy.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'kv'",
        [],
        |row| row.get(0),
    )?;
    if tables == 0 {
        return Err(ImportError::NotCacheDb);
    }
    let prefix = if cache_id.is_empty() {
        String::new()
    } else {
        format!("{cache_id}:")
    };
    // Only the imported keys, as text: `dns:v2:` values are BLOBs, and DNS and
    // FakeIP rows are unbounded.
    let exact = ["clash_mode", "selector:GLOBAL"].map(|key| format!("{prefix}{key}"));
    let ranges = ["selector:tcp:", "selector:udp:", "delay:"].map(|key| {
        let start = format!("{prefix}{key}");
        // Every range prefix ends in ':', and ';' is the next byte.
        let end = format!("{};", &start[..start.len() - 1]);
        (start, end)
    });
    let mut statement = legacy.prepare(
        "SELECT key, value FROM kv WHERE typeof(value) = 'text' AND (key = ?1 OR key = ?2
           OR (key >= ?3 AND key < ?4) OR (key >= ?5 AND key < ?6) OR (key >= ?7 AND key < ?8))",
    )?;
    let mut rows = statement.query(params![
        exact[0],
        exact[1],
        ranges[0].0,
        ranges[0].1,
        ranges[1].0,
        ranges[1].1,
        ranges[2].0,
        ranges[2].1,
    ])?;
    let now = now_unix();
    while let Some(row) = rows.next()? {
        let key: String = row.get(0)?;
        let value: String = row.get(1)?;
        if let Some(key) = key.strip_prefix(&prefix) {
            import_row(&transaction, key, &value, now, scope)?;
        }
    }
    // The copy is cache data: it must leave the strict headroom intact.
    if super::used_pages(&transaction)? > state.cache_budget_pages() {
        return Err(ImportError::OverBudget);
    }
    transaction.execute(
        "INSERT INTO legacy_import (source, done_at) VALUES (?1, ?2)",
        params![source, done_at()],
    )?;
    transaction.commit()?;
    Ok(true)
}

fn import_row(
    connection: &Connection,
    key: &str,
    value: &str,
    now: u64,
    scope: &ImportScope,
) -> rusqlite::Result<()> {
    if key == "clash_mode" || key == "selector:GLOBAL" {
        let target = if key == "clash_mode" {
            "mode"
        } else {
            "global"
        };
        connection.execute(
            "INSERT OR IGNORE INTO clash_state (key, value) VALUES (?1, ?2)",
            params![target, value],
        )?;
    } else if let Some((network, group)) = key
        .strip_prefix("selector:tcp:")
        .map(|group| ("tcp", group))
        .or_else(|| {
            key.strip_prefix("selector:udp:")
                .map(|group| ("udp", group))
        })
    {
        if !scope.selector_groups.contains(group) {
            return Ok(());
        }
        connection.execute(
            "INSERT OR IGNORE INTO selector (grp, network, member) VALUES (?1, ?2, ?3)",
            params![group, network, value],
        )?;
    } else if let Some(node) = key
        .strip_prefix("delay:")
        .filter(|node| scope.nodes.contains(*node))
    {
        let sample = serde_json::from_str::<serde_json::Value>(value).ok();
        let field = |name| {
            sample
                .as_ref()
                .and_then(|sample| sample.get(name))
                .and_then(serde_json::Value::as_i64)
        };
        if let (Some(delay_ms), Some(measured_at)) = (field("delay_ms"), field("measured_at"))
            && delay_ms > 0
            && measured_at > 0
            && now.saturating_sub(measured_at as u64) <= DELAY_MAX_AGE_SECS
        {
            connection.execute(
                "INSERT OR IGNORE INTO delay_sample (node, delay_ms, measured_at) VALUES (?1, ?2, ?3)",
                params![node, delay_ms, measured_at],
            )?;
        }
    }
    Ok(())
}

/// Sidecars first, so a crash never leaves a `-wal` beside a new file of the
/// same name. `<name>.corrupt-*` copies are diagnostics, not cache rows, and stay.
fn remove_cache_db(path: &Path) {
    let (Some(directory), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let name = name.to_string_lossy();
    let targets = [
        directory.join(format!("{name}-wal")),
        directory.join(format!("{name}-shm")),
        path.to_path_buf(),
    ];
    for target in targets {
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, path = %target.display(), "legacy cache.db removal failed");
                return;
            }
        }
    }
    if let Err(error) = std::fs::File::open(directory).and_then(|directory| directory.sync_all()) {
        tracing::warn!(%error, "legacy cache.db directory sync failed");
    }
}

#[cfg(test)]
mod tests;
