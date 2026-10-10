//! Subscription bodies in the state db's `subscription_body` table.
//!
//! Bodies are keyed by `subscription_filename`, the fetch identity. Together
//! they are capped at `MAX_TOTAL_BYTES`; a write that would pass the cap first
//! deletes bodies of subscriptions no longer enabled, and is refused if that is
//! not enough, which leaves the previous body in place.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use honk_config::diagnostic::{DetailedDiagnostic, report_detailed_diagnostics};
use honk_config::node::Node;
use honk_config::subscription::Subscription;
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use rusqlite::{Connection, MAIN_DB, OptionalExtension as _, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use super::{SUBSCRIPTION_STORE_DIR, parse_subscription_content_with_diagnostics};
use crate::state::{StateDb, effective_uid};

/// All stored bodies together.
const MAX_TOTAL_BYTES: i64 = 32 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;

/// Durable raw subscription bodies keyed by their fetch identity.
#[derive(Clone)]
pub struct SubscriptionStore {
    state: Arc<StateDb>,
}

impl std::fmt::Debug for SubscriptionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionStore").finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
enum PutError {
    #[error("stored subscription bodies would exceed 32 MiB")]
    TooLarge,
    #[error("subscription store operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

impl SubscriptionStore {
    pub fn new(state: Arc<StateDb>) -> Self {
        Self { state }
    }

    /// Records the enabled subscriptions of the configuration being published;
    /// `put_body` may delete any other body to stay under the cap, and
    /// maintenance deletes the body of one with `cache` off.
    pub(crate) fn set_enabled<'a>(
        &self,
        subscriptions: impl IntoIterator<Item = &'a Subscription>,
    ) {
        self.state.set_enabled_subscriptions(
            subscriptions
                .into_iter()
                .filter(|sub| sub.cache)
                .map(subscription_filename)
                .collect(),
        );
    }

    pub async fn load_nodes(&self, sub: &Subscription) -> anyhow::Result<Option<Vec<Node>>> {
        let mut diagnostics = Vec::new();
        let result = self
            .load_nodes_with_diagnostics(sub, &mut diagnostics)
            .await;
        report_detailed_diagnostics(&diagnostics);
        result
    }

    pub async fn load_nodes_with_diagnostics(
        &self,
        sub: &Subscription,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> anyhow::Result<Option<Vec<Node>>> {
        if !sub.cache {
            return Ok(None);
        }
        let key = subscription_filename(sub);
        let state = Arc::clone(&self.state);
        let body = tokio::task::spawn_blocking(move || read_body(&state.strict(), &key))
            .await?
            .context("read subscription body from the state db")?;
        let Some(body) = body else {
            return Ok(None);
        };
        let content = String::from_utf8(body).context("stored subscription body is not UTF-8")?;
        parse_subscription_content_with_diagnostics(sub, &content, diagnostics)
            .map(Some)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    pub(crate) async fn store_content(
        &self,
        sub: &Subscription,
        content: String,
    ) -> anyhow::Result<()> {
        if !sub.cache {
            return Ok(());
        }
        let key = subscription_filename(sub);
        let state = Arc::clone(&self.state);
        tokio::task::spawn_blocking(move || put_body(&state, &key, content.as_bytes()))
            .await?
            .context("write subscription body to the state db")
    }

    /// A store over a new state db in `data_dir`.
    #[cfg(test)]
    pub(crate) fn in_dir(data_dir: &Path) -> Self {
        Self::new(Arc::new(StateDb::open(data_dir).expect("state db")))
    }

    #[cfg(test)]
    pub(crate) fn key(sub: &Subscription) -> String {
        subscription_filename(sub)
    }

    #[cfg(test)]
    pub(super) fn state(&self) -> &StateDb {
        &self.state
    }

    #[cfg(test)]
    pub(crate) fn remove_body(&self, sub: &Subscription) {
        self.state
            .strict()
            .execute(
                "DELETE FROM subscription_body WHERE key = ?1",
                [subscription_filename(sub)],
            )
            .unwrap();
    }

    /// Makes every later write fail.
    #[cfg(test)]
    pub(super) fn refuse_writes(&self) {
        self.state
            .strict()
            .execute_batch("PRAGMA query_only = ON")
            .unwrap();
    }

    #[cfg(test)]
    pub(super) fn body(&self, sub: &Subscription) -> Option<String> {
        read_body(&self.state.strict(), &subscription_filename(sub))
            .unwrap()
            .map(|body| String::from_utf8(body).unwrap())
    }
}

/// Stored bodies read through a read-only connection, for offline validation.
#[cfg(feature = "native-api")]
pub(crate) struct StoredBodies {
    data_dir: PathBuf,
    connection: Connection,
    _directory: File,
}

#[cfg(feature = "native-api")]
impl StoredBodies {
    /// `None` when `data_dir` has no state db: nothing was ever stored.
    pub(crate) fn open(data_dir: &Path) -> io::Result<Option<Self>> {
        let path = data_dir
            .join(crate::state::STATE_DIR)
            .join(crate::state::DB_FILE);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        let (directory, connection) =
            crate::state::open_read_only(data_dir).map_err(io::Error::other)?;
        Ok(Some(Self {
            data_dir: data_dir.to_path_buf(),
            connection,
            _directory: directory,
        }))
    }

    /// The stored body, not yet read, so its length can be checked first.
    pub(crate) fn find(&self, sub: &Subscription) -> io::Result<Option<StoredBody<'_>>> {
        let key = subscription_filename(sub);
        let Some((blob, length)) = open_body(&self.connection, &key).map_err(io::Error::other)?
        else {
            return Ok(None);
        };
        Ok(Some(StoredBody {
            label: self
                .data_dir
                .join(format!("state/honk.db#subscription/{key}")),
            length,
            blob,
        }))
    }
}

#[cfg(feature = "native-api")]
pub(crate) struct StoredBody<'a> {
    /// The dependency label naming the body.
    pub(crate) label: PathBuf,
    pub(crate) length: usize,
    blob: rusqlite::blob::Blob<'a>,
}

#[cfg(feature = "native-api")]
impl StoredBody<'_> {
    /// Allocated once at its final size and filled in place.
    pub(crate) fn read(mut self) -> io::Result<Arc<[u8]>> {
        let mut body: Arc<[u8]> = std::iter::repeat_n(0, self.length).collect();
        self.blob
            .read_exact(Arc::get_mut(&mut body).expect("a new Arc is unique"))?;
        Ok(body)
    }
}

/// The body's blob handle and length, so the caller reads it straight into
/// its final buffer.
fn open_body<'a>(
    connection: &'a Connection,
    key: &str,
) -> rusqlite::Result<Option<(rusqlite::blob::Blob<'a>, usize)>> {
    let Some((rowid, length)): Option<(i64, i64)> = connection
        .query_row(
            "SELECT rowid, length(body) FROM subscription_body WHERE key = ?1",
            [key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let blob = connection.blob_open(MAIN_DB, c"subscription_body", c"body", rowid, true)?;
    Ok(Some((blob, usize::try_from(length).unwrap_or(0))))
}

fn read_body(connection: &Connection, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
    let Some((mut blob, length)) = open_body(connection, key)? else {
        return Ok(None);
    };
    let mut body = vec![0; length];
    blob.read_exact(&mut body)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
    Ok(Some(body))
}

/// The one write path, used by fetches and by the `.sub` import: stores `body`
/// under `key` in one strict transaction, deleting bodies of subscriptions
/// that are no longer enabled only when needed to stay under the cap.
fn put_body(state: &StateDb, key: &str, body: &[u8]) -> Result<(), PutError> {
    let mut connection = state.strict();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let enabled = state.enabled_subscriptions();
    put_body_in(&transaction, key, body, enabled.as_ref(), true)?;
    transaction.commit()?;
    Ok(())
}

/// `replace: false` keeps an existing row, as the import wants.
fn put_body_in(
    connection: &Connection,
    key: &str,
    body: &[u8],
    enabled: Option<&HashSet<String>>,
    replace: bool,
) -> Result<bool, PutError> {
    if !replace
        && connection
            .query_row(
                "SELECT 1 FROM subscription_body WHERE key = ?1",
                [key],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
    {
        return Ok(false);
    }
    let length = i64::try_from(body.len()).map_err(|_| PutError::TooLarge)?;
    let others = |connection: &Connection| -> rusqlite::Result<i64> {
        connection.query_row(
            "SELECT coalesce(sum(length(body)), 0) FROM subscription_body WHERE key != ?1",
            [key],
            |row| row.get(0),
        )
    };
    if others(connection)? + length > MAX_TOTAL_BYTES {
        let Some(enabled) = enabled else {
            return Err(PutError::TooLarge);
        };
        let keys: Vec<String> = connection
            .prepare("SELECT key FROM subscription_body WHERE key != ?1")?
            .query_map([key], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for stale in keys.iter().filter(|stale| !enabled.contains(*stale)) {
            connection.execute("DELETE FROM subscription_body WHERE key = ?1", [stale])?;
        }
        if others(connection)? + length > MAX_TOTAL_BYTES {
            return Err(PutError::TooLarge);
        }
    }
    let fetched_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64);
    connection.execute(
        "INSERT OR REPLACE INTO subscription_body (key, fetched_at, body) VALUES (?1, ?2, zeroblob(?3))",
        params![key, fetched_at, length],
    )?;
    let rowid = connection.last_insert_rowid();
    let mut blob = connection.blob_open(MAIN_DB, c"subscription_body", c"body", rowid, false)?;
    for chunk in body.chunks(CHUNK) {
        blob.write_all(chunk)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
    }
    Ok(true)
}

/// Deletes bodies whose key was outside the enabled set at this call and the
/// previous one; `previous` carries the keys between calls.
pub(crate) fn prune_bodies(
    state: &StateDb,
    previous: &mut HashSet<String>,
) -> rusqlite::Result<()> {
    let mut connection = state.strict();
    let enabled = state.enabled_subscriptions();
    let Some(enabled_keys) = enabled.as_ref() else {
        return Ok(());
    };
    let keys: Vec<String> = connection
        .prepare("SELECT key FROM subscription_body")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let current: HashSet<String> = keys
        .into_iter()
        .filter(|key| !enabled_keys.contains(key))
        .collect();
    let expired: Vec<&String> = current.intersection(previous).collect();
    let deleted = !expired.is_empty();
    if deleted {
        let transaction = connection.transaction()?;
        for key in expired {
            transaction.execute("DELETE FROM subscription_body WHERE key = ?1", [key])?;
        }
        transaction.commit()?;
    }
    drop(enabled);
    if deleted {
        crate::state::incremental_vacuum(&connection)?;
    }
    *previous = current;
    Ok(())
}

/// A `.sub` directory from before the state db; the copied files are removed
/// after the instance lock by `remove`.
pub(crate) struct LegacySubscriptionStore {
    root: PathBuf,
    directory: File,
    /// Files whose body the state db now holds.
    copied: HashSet<String>,
}

impl LegacySubscriptionStore {
    /// Copies the bodies of `subscriptions` that are enabled from the first
    /// private `.sub` directory in the order older releases searched. Existing
    /// rows win. Other bodies, and those that could not be copied, stay for a
    /// later start that enables them. `None` when there is no store or the
    /// copy failed. Nothing is removed here.
    pub(crate) fn import(
        state: &StateDb,
        roots: impl IntoIterator<Item = PathBuf>,
        subscriptions: &[Subscription],
    ) -> Option<Self> {
        let (root, directory) = roots.into_iter().find_map(|root| {
            let directory = open_store_directory(&root).ok()?;
            inspect_store_directory(&directory).ok()?;
            Some((root, directory))
        })?;
        match copy_legacy(state, &directory, subscriptions) {
            Ok(copied) => Some(Self {
                root,
                directory,
                copied,
            }),
            Err(error) => {
                tracing::warn!(%error, directory = %root.display(), "legacy subscription store import failed");
                None
            }
        }
    }

    /// Unlinks the copied `*.sub` and every `.*.tmp` in the directory through
    /// its FD, then removes the directory if that left it empty. Other legacy
    /// locations are not touched.
    pub(crate) fn remove(self) {
        let result = (|| -> io::Result<()> {
            use std::os::fd::AsRawFd as _;
            // The listing goes through the held FD, so a replaced path is not read.
            let listing =
                std::fs::read_dir(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))?;
            for entry in listing {
                let name = entry?.file_name().to_string_lossy().into_owned();
                if self.copied.contains(&name) || (name.starts_with('.') && name.ends_with(".tmp"))
                {
                    nix::unistd::unlinkat(
                        &self.directory,
                        name.as_str(),
                        nix::unistd::UnlinkatFlags::NoRemoveDir,
                    )?;
                }
            }
            self.directory.sync_all()
        })();
        match result {
            Ok(()) => {
                if std::fs::remove_dir(&self.root).is_ok() {
                    tracing::info!(directory = %self.root.display(), "removed the legacy subscription store");
                }
            }
            Err(error) => {
                tracing::warn!(%error, directory = %self.root.display(), "legacy subscription store removal failed")
            }
        }
    }
}

/// The keys of the enabled bodies the state db holds after the copy.
fn copy_legacy(
    state: &StateDb,
    directory: &File,
    subscriptions: &[Subscription],
) -> Result<HashSet<String>, PutError> {
    let mut connection = state.strict();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut copied = HashSet::new();
    let enabled: HashSet<String> = subscriptions
        .iter()
        .filter(|sub| sub.enabled)
        .map(subscription_filename)
        .collect();
    for key in &enabled {
        let mut body = Vec::new();
        let limit = super::MAX_SUBSCRIPTION_BYTES as u64 + 1;
        match open_store_file(directory, key)
            .and_then(|file| file.take(limit).read_to_end(&mut body))
        {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                tracing::warn!(%error, "legacy subscription body is unreadable; not copied");
                continue;
            }
        }
        if body.len() > super::MAX_SUBSCRIPTION_BYTES {
            tracing::warn!("legacy subscription body exceeds 8 MiB; not copied");
            continue;
        }
        match put_body_in(&transaction, key, &body, Some(&enabled), false) {
            Ok(_) => {
                copied.insert(key.clone());
            }
            Err(PutError::TooLarge) => {
                tracing::warn!("legacy subscription body would pass 32 MiB in total; not copied");
            }
            Err(error) => return Err(error),
        }
    }
    transaction.commit()?;
    Ok(copied)
}

/// Where older releases kept `.sub`, in their search order.
pub(crate) fn legacy_store_roots() -> [PathBuf; 3] {
    [
        honk_config::paths::data_dir().join(SUBSCRIPTION_STORE_DIR),
        Path::new(honk_config::paths::LEGACY_DATA_DIR).join(SUBSCRIPTION_STORE_DIR),
        PathBuf::from(SUBSCRIPTION_STORE_DIR),
    ]
}

fn subscription_cache_user_agent(sub: &Subscription) -> &str {
    // The request UA may change with the binary; the cache identity must not.
    sub.user_agent.as_deref().unwrap_or_default()
}

/// Full fetch identity, matching the cache filename key: URL plus configured
/// UA plus headers. URL-only reload matching can swap identities between
/// same-URL subscriptions with different fetch options.
pub(crate) fn same_subscription_fetch_identity(a: &Subscription, b: &Subscription) -> bool {
    a.url == b.url
        && subscription_cache_user_agent(a) == subscription_cache_user_agent(b)
        && a.headers == b.headers
}

fn subscription_filename(sub: &Subscription) -> String {
    fn add_part(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    let mut hasher = Sha256::new();
    add_part(&mut hasher, sub.url.as_bytes());
    add_part(&mut hasher, subscription_cache_user_agent(sub).as_bytes());
    for header in &sub.headers {
        add_part(&mut hasher, header.key.as_bytes());
        add_part(&mut hasher, header.value.as_bytes());
    }
    use base64::Engine as _;
    format!(
        "{}.sub",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
    )
}

fn open_store_directory(root: &Path) -> io::Result<File> {
    open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)
}

fn inspect_store_directory(directory: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != effective_uid() || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "subscription store directory is not private to the process",
        ));
    }
    Ok(())
}

fn open_store_file(directory: &File, filename: &str) -> io::Result<File> {
    let descriptor = openat(
        directory,
        filename,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("subscription cache is not a regular file"));
    }
    if metadata.uid() != effective_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "subscription cache is not owned by the process",
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "subscription cache is writable by another user",
        ));
    }
    Ok(file)
}
