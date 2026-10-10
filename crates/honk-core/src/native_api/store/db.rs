//! Configuration revisions in the state database (`crate::state`).
//!
//! A write is activated first and recorded after: `commit` only fences `head`,
//! and `promote` inserts the revision and moves `head` in one transaction, so a
//! crash in between restarts from the old `head` that the client never saw replaced.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use honk_config::Config;
use honk_config::diagnostic::{DetailedDiagnostic, DiagnosticSources, SettingPath};
use honk_config::error::{DetailedConfigError, ErrorCategory};
use honk_config::parser::source_edit::{inline_sources, restore_listener_secrets};
use honk_config::parser::{LoadedConfig, SourceLimits, SourceSnapshot};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::super::ApiError;
use super::super::config::ListenerSecrets;
use super::super::config_write::WriteError;
use crate::configuration::{MAX_SOURCE_BYTES, MAX_SOURCES, digest};
use crate::state::{StateDb, StateError, log_sql};

pub(crate) const MAX_REVISIONS: usize = 50;
/// Of stored JSON, which escaping can make larger than the source bytes.
const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("configuration database is unavailable")]
    Unavailable,
    #[error("configuration database path is unsafe")]
    Unsafe,
    #[error("configuration database is corrupt")]
    Corrupt,
    #[error("configuration database has a foreign application id or a newer schema")]
    Unsupported,
    #[error("configuration database already holds a revision")]
    NotEmpty,
    #[error("configuration revision is invalid")]
    Invalid,
    #[error("configuration revision declares a listener secret")]
    SecretSource,
    #[error("configuration revision contains a listener secret")]
    SecretContent,
    #[error("configuration revision exceeds 16 MiB of stored JSON")]
    TooLarge,
    #[error("state database is locked by `honk-core admin reset`")]
    Locked,
}

impl From<StateError> for StoreError {
    fn from(error: StateError) -> Self {
        match error {
            StateError::Unavailable => Self::Unavailable,
            StateError::Unsafe(_) => Self::Unsafe,
            StateError::Corrupt => Self::Corrupt,
            StateError::Unsupported => Self::Unsupported,
            StateError::Locked | StateError::InUse => Self::Locked,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    Import,
    Write,
    Activate,
}

impl Origin {
    fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Write => "write",
            Self::Activate => "activate",
        }
    }
}

/// One row of the revision list; content stays in the db.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RevisionInfo {
    pub(crate) number: i64,
    pub(crate) parent: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) principal: String,
    pub(crate) origin: String,
    pub(crate) content_sha256: String,
    pub(crate) bytes: i64,
    /// `(name, sha256)` in loader preorder.
    pub(crate) sources: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StoredSecrets {
    pub(crate) native_api: String,
    pub(crate) clash_api: String,
}

/// Head fence for one source of the active revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RevisionPin {
    pub(crate) number: i64,
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
}

/// An activated candidate that `promote` still has to record.
pub(crate) struct Pending {
    parent: i64,
    sources: Vec<StoredSource>,
    principal: String,
    origin: Origin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSource {
    name: String,
    parent: Option<usize>,
    content: String,
    sha256: String,
}

struct Revision {
    sources: Vec<StoredSource>,
}

pub(crate) struct DbStore {
    state: Arc<StateDb>,
    entry: PathBuf,
    root: PathBuf,
    /// The `-c` entry this process started with; `import` reads it.
    import_entry: PathBuf,
    /// Set when the daemon may run something `head` does not record; cleared by
    /// restart or by re-activating `head`.
    blocked: AtomicBool,
    /// `(head, parent)` as last read or written, so readers need no SQLite call.
    head: Mutex<Option<(i64, Option<i64>)>>,
    secrets: Mutex<StoredSecrets>,
    #[cfg(test)]
    pub(crate) fail_promote: AtomicBool,
    #[cfg(test)]
    lose_commit_reply: AtomicBool,
}

impl DbStore {
    /// Opens or creates the db. `entry` names the main source when the db is still
    /// empty; otherwise the active revision's own entry wins.
    pub(crate) fn open(state: Arc<StateDb>, entry: &Path) -> Result<Self, StoreError> {
        let import_entry = lexical(entry)?;
        let (root_entry, head, secrets) = {
            let connection = state.strict();
            let root_entry = match active_revision(&connection)? {
                Some((_, root, revision)) => root.join(&revision.sources[0].name),
                None => import_entry.clone(),
            };
            (
                root_entry,
                head_and_parent(&connection)?,
                listener_secrets(&connection)?,
            )
        };
        let root = root_entry
            .parent()
            .ok_or(StoreError::Invalid)?
            .to_path_buf();
        Ok(Self {
            state,
            entry: root_entry,
            root,
            import_entry,
            blocked: AtomicBool::new(false),
            head: Mutex::new(head),
            secrets: Mutex::new(secrets),
            #[cfg(test)]
            fail_promote: AtomicBool::new(false),
            #[cfg(test)]
            lose_commit_reply: AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    pub(crate) fn open_in(data_dir: &Path, entry: &Path) -> Result<Self, StoreError> {
        Self::open(Arc::new(StateDb::open(data_dir)?), entry)
    }

    pub(crate) fn state(&self) -> Arc<StateDb> {
        Arc::clone(&self.state)
    }

    /// The cached `(head, parent)`; never touches SQLite.
    pub(crate) fn cached_head(&self) -> Option<(i64, Option<i64>)> {
        *self.head.lock()
    }

    pub(crate) fn listener_secrets(&self) -> StoredSecrets {
        self.secrets.lock().clone()
    }

    pub(crate) fn blocked(&self) -> bool {
        self.blocked.load(Ordering::Acquire)
    }

    /// The daemon runs `head` again after a re-activation.
    pub(crate) fn unblock(&self) {
        self.blocked.store(false, Ordering::Release);
    }

    pub(crate) fn revision_exists(&self, number: i64) -> Result<bool, StoreError> {
        self.state
            .strict()
            .query_row("SELECT 1 FROM revision WHERE number = ?1", [number], |_| {
                Ok(())
            })
            .optional()
            .map(|row| row.is_some())
            .map_err(sql)
    }

    pub(crate) fn entry(&self) -> &Path {
        &self.entry
    }

    pub(crate) fn head(&self) -> Result<Option<i64>, StoreError> {
        head(&self.state.strict())
    }

    pub(crate) fn import_entry(&self) -> &Path {
        &self.import_entry
    }

    /// The durable head and its revision list, newest first, from one read transaction.
    pub(crate) fn revisions(&self) -> Result<(Option<i64>, Vec<RevisionInfo>), StoreError> {
        let mut connection = self.state.strict();
        let transaction = connection.transaction().map_err(sql)?;
        let active = head(&transaction)?;
        let mut statement = transaction
            .prepare(
                "SELECT number, parent, created_at, principal, origin, content_sha256, bytes, sources
                 FROM revision ORDER BY number DESC",
            )
            .map_err(sql)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    RevisionInfo {
                        number: row.get(0)?,
                        parent: row.get(1)?,
                        created_at: row.get(2)?,
                        principal: row.get(3)?,
                        origin: row.get(4)?,
                        content_sha256: row.get(5)?,
                        bytes: row.get(6)?,
                        sources: Vec::new(),
                    },
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(sql)?;
        let mut revisions = Vec::new();
        for row in rows {
            let (mut info, sources) = row.map_err(sql)?;
            if digest(sources.as_bytes()) != info.content_sha256 {
                return Err(StoreError::Corrupt);
            }
            let sources: Vec<StoredSource> =
                serde_json::from_str(&sources).map_err(|_| StoreError::Corrupt)?;
            info.sources = sources
                .into_iter()
                .map(|source| (source.name, source.sha256))
                .collect();
            revisions.push(info);
        }
        Ok((active, revisions))
    }

    /// Loads revision `number` as the loader sees it, secrets re-applied.
    pub(crate) fn load_revision(
        &self,
        number: i64,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Option<LoadedConfig>, StoreError> {
        let (revision, secrets) = {
            let connection = self.state.strict();
            let Some((root, revision)) = revision(&connection, number)? else {
                return Ok(None);
            };
            if root != self.root {
                return Err(StoreError::Invalid);
            }
            (revision, self.secrets.lock().clone())
        };
        let sources = revision
            .sources
            .into_iter()
            .map(|source| (self.root.join(source.name), Arc::from(source.content)))
            .collect();
        self.load_sources(&sources, &secrets, diagnostics)
            .map(Some)
            .map_err(|_| StoreError::Invalid)
    }

    /// A candidate that did not come from editing one pinned source.
    pub(crate) fn stage(
        &self,
        candidate: &[SourceSnapshot],
        principal: &str,
        origin: Origin,
    ) -> Result<Pending, WriteError> {
        if self.blocked.load(Ordering::Acquire) {
            return Err(WriteError::Unavailable);
        }
        let parent = self
            .head()
            .map_err(|_| WriteError::Unavailable)?
            .ok_or(WriteError::Unavailable)?;
        let sources = self.stored_now(candidate)?;
        Ok(Pending {
            parent,
            sources,
            principal: principal.to_owned(),
            origin,
        })
    }

    fn load_sources(
        &self,
        sources: &HashMap<PathBuf, Arc<str>>,
        secrets: &StoredSecrets,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<LoadedConfig, DetailedConfigError> {
        let mut loaded = Config::from_dae_sources_in_memory(
            &self.entry,
            sources,
            SourceLimits::DEFAULT,
            diagnostics,
        )?;
        loaded.config.experimental.native_api.secret = secrets.native_api.clone();
        loaded.config.experimental.clash_api.secret = secrets.clash_api.clone();
        Ok(loaded)
    }

    /// Records the first revision; refused once any revision exists.
    /// `forbidden` holds every listener secret value the operator's tree carried.
    pub(crate) fn initialize(
        &self,
        sources: &[SourceSnapshot],
        forbidden: &ListenerSecrets,
        secrets: &StoredSecrets,
        principal: &str,
    ) -> Result<i64, StoreError> {
        let stored = self.stored(sources, &forbidden.clone().with_all(secrets))?;
        let mut connection = self.state.strict();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        if head(&transaction)?.is_some() {
            return Err(StoreError::NotEmpty);
        }
        let number = insert(
            &transaction,
            None,
            &self.root,
            &stored,
            principal,
            Origin::Import,
        )?;
        for (api, value) in [
            ("native_api", &secrets.native_api),
            ("clash_api", &secrets.clash_api),
        ] {
            if !value.is_empty() {
                transaction
                    .execute(
                        "INSERT INTO listener_secret (api, value) VALUES (?1, ?2)",
                        params![api, value],
                    )
                    .map_err(sql)?;
            }
        }
        transaction
            .execute("INSERT INTO head (id, active) VALUES (1, ?1)", [number])
            .map_err(sql)?;
        transaction.commit().map_err(sql)?;
        *self.head.lock() = Some((number, None));
        *self.secrets.lock() = secrets.clone();
        Ok(number)
    }

    /// Lexical: the db holds virtual paths, so nothing under `root` is opened.
    pub(crate) fn resolve(&self, label: &str) -> Result<PathBuf, ApiError> {
        let input = Path::new(label);
        let path = if input.is_absolute() {
            input
                .strip_prefix(&self.root)
                .map_err(|_| super::super::config::invalid())?
        } else {
            input
        };
        let path: PathBuf = path.components().collect();
        valid_name(&path).map_err(|_| super::super::config::invalid())?;
        Ok(self.root.join(path))
    }

    pub(crate) fn load(
        &self,
        overlay: &HashMap<PathBuf, Arc<str>>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<LoadedConfig, DetailedConfigError> {
        let revision = active_revision(&self.state.strict())
            .ok()
            .flatten()
            .map(|(_, _, revision)| revision);
        let Some(revision) = revision else {
            return Err(store_unavailable());
        };
        let secrets = self.secrets.lock().clone();
        let mut sources: HashMap<PathBuf, Arc<str>> = revision
            .sources
            .into_iter()
            .map(|source| (self.root.join(source.name), Arc::from(source.content)))
            .collect();
        sources.extend(
            overlay
                .iter()
                .map(|(path, content)| (path.clone(), content.clone())),
        );
        self.load_sources(&sources, &secrets, diagnostics)
    }

    pub(crate) fn pin(&self, path: &Path) -> Result<RevisionPin, WriteError> {
        if self.blocked() {
            return Err(WriteError::Unavailable);
        }
        let connection = self.state.strict();
        let (number, _, revision) = active_revision(&connection)
            .map_err(|_| WriteError::Unavailable)?
            .ok_or(WriteError::Unavailable)?;
        let source = revision
            .sources
            .iter()
            .find(|source| self.root.join(&source.name) == path)
            .ok_or(WriteError::Conflict)?;
        Ok(RevisionPin {
            number,
            path: path.to_path_buf(),
            sha256: source.sha256.clone(),
        })
    }

    pub(crate) fn recheck(&self, pin: &RevisionPin) -> Result<(), WriteError> {
        if self.blocked.load(Ordering::Acquire) {
            return Err(WriteError::Unavailable);
        }
        match head(&self.state.strict()) {
            Ok(Some(number)) if number == pin.number => Ok(()),
            Ok(_) => Err(WriteError::Conflict),
            Err(_) => Err(WriteError::Unavailable),
        }
    }

    /// Fences `head` and runs `before`; nothing is written until `promote`.
    pub(crate) fn commit(
        &self,
        pin: RevisionPin,
        content: &str,
        candidate: &[SourceSnapshot],
        principal: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<Pending, WriteError> {
        if !candidate
            .iter()
            .any(|source| source.path == pin.path && source.content.as_ref() == content)
        {
            return Err(WriteError::Conflict);
        }
        let sources = self.stored_now(candidate)?;
        self.recheck(&pin)?;
        before()?;
        self.recheck(&pin)?;
        Ok(Pending {
            parent: pin.number,
            sources,
            principal: principal.to_owned(),
            origin: Origin::Write,
        })
    }

    /// Records an activated candidate as the new `head`. Any failure blocks later
    /// writes, because the daemon now runs what `head` does not describe.
    pub(crate) fn promote(&self, pending: Pending) -> Result<i64, WriteError> {
        let result = self.promote_inner(&pending);
        if result.is_err() {
            self.block();
        }
        result
    }

    pub(crate) fn block(&self) {
        self.blocked.store(true, Ordering::Release);
    }

    fn promote_inner(&self, pending: &Pending) -> Result<i64, WriteError> {
        if self.blocked.load(Ordering::Acquire) {
            return Err(WriteError::Unavailable);
        }
        #[cfg(test)]
        if self.fail_promote.load(Ordering::Acquire) {
            return Err(WriteError::Unavailable);
        }
        let mut connection = self.state.strict();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(write_sql)?;
        if head(&transaction).map_err(|_| WriteError::Unavailable)? != Some(pending.parent) {
            return Err(WriteError::Conflict);
        }
        let number = insert(
            &transaction,
            Some(pending.parent),
            &self.root,
            &pending.sources,
            &pending.principal,
            pending.origin,
        )
        .map_err(|_| WriteError::Unavailable)?;
        transaction
            .execute("UPDATE head SET active = ?1 WHERE id = 1", [number])
            .map_err(write_sql)?;
        prune(&transaction, number).map_err(write_sql)?;
        let promoted = head_and_parent(&transaction).map_err(|_| WriteError::Unavailable)?;
        let committed = transaction.commit();
        #[cfg(test)]
        let committed = committed.and_then(|()| {
            if self.lose_commit_reply.swap(false, Ordering::AcqRel) {
                Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                    None,
                ))
            } else {
                Ok(())
            }
        });
        if let Err(error) = committed {
            log_sql(&error);
            return match head_and_parent(&connection) {
                Ok(Some((active, parent))) if active == number => {
                    *self.head.lock() = Some((active, parent));
                    Ok(number)
                }
                _ => Err(WriteError::Unavailable),
            };
        }
        *self.head.lock() = promoted;
        Ok(number)
    }

    /// `stored` against the listener secrets this db already holds.
    fn stored_now(&self, candidate: &[SourceSnapshot]) -> Result<Vec<StoredSource>, WriteError> {
        let forbidden = ListenerSecrets::empty().with_all(&self.secrets.lock());
        self.stored(candidate, &forbidden)
            .map_err(|error| match error {
                StoreError::Invalid => WriteError::UnsafePath,
                StoreError::SecretSource => WriteError::SecretSource,
                StoreError::SecretContent => WriteError::SecretContent,
                StoreError::TooLarge => WriteError::TooLarge,
                _ => WriteError::Unavailable,
            })
    }

    /// Refuses any source whose content or name still carries a `forbidden` value.
    fn stored(
        &self,
        sources: &[SourceSnapshot],
        forbidden: &ListenerSecrets,
    ) -> Result<Vec<StoredSource>, StoreError> {
        let bytes: usize = sources.iter().map(|source| source.content.len()).sum();
        if sources.is_empty()
            || sources.len() > MAX_SOURCES
            || bytes > MAX_SOURCE_BYTES
            || sources[0].path != self.entry
        {
            return Err(StoreError::Invalid);
        }
        let stored = sources
            .iter()
            .map(|source| {
                if source.contains_api_secret {
                    return Err(StoreError::SecretSource);
                }
                if forbidden.contains(&source.content)
                    || forbidden.contains(&source.path.to_string_lossy())
                {
                    return Err(StoreError::SecretContent);
                }
                let name = source
                    .path
                    .strip_prefix(&self.root)
                    .map_err(|_| StoreError::Invalid)?;
                valid_name(name)?;
                Ok(StoredSource {
                    name: name.to_str().ok_or(StoreError::Invalid)?.to_owned(),
                    parent: source.parent,
                    content: source.content.to_string(),
                    sha256: digest(source.content.as_bytes()),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if json_len(&stored) > MAX_RETAINED_BYTES {
            return Err(StoreError::TooLarge);
        }
        Ok(stored)
    }
}

/// The active revision as one runnable document, read without writing the db
/// whether or not a daemon holds it open.
pub(crate) fn export(data_dir: &Path, with_secrets: bool) -> Result<String, StoreError> {
    let (_directory, mut connection) = crate::state::open_read_only(data_dir)?;
    let (root, revision, secrets) = {
        let transaction = connection.transaction().map_err(sql)?;
        let (_, root, revision) = active_revision(&transaction)?.ok_or(StoreError::Invalid)?;
        let secrets = listener_secrets(&transaction)?;
        transaction.commit().map_err(sql)?;
        (root, revision, secrets)
    };
    let entry = root.join(&revision.sources[0].name);
    let sources = revision
        .sources
        .into_iter()
        .map(|source| (root.join(source.name), Arc::from(source.content)))
        .collect();
    let loaded = Config::from_dae_sources_in_memory(
        &entry,
        &sources,
        SourceLimits::DEFAULT,
        &mut Vec::new(),
    )
    .map_err(|_| StoreError::Corrupt)?;
    let text = inline_sources(&loaded.sources).map_err(|_| StoreError::Corrupt)?;
    if with_secrets {
        restore_listener_secrets(&text, &secrets.native_api, &secrets.clash_api)
            .map_err(|_| StoreError::Corrupt)
    } else if secrets == StoredSecrets::default() {
        Ok(text)
    } else {
        let (text, _) = ListenerSecrets::empty().with_all(&secrets).mask(&text);
        Ok(format!("# listener secrets omitted\n{text}"))
    }
}

/// Writes `export` to a new 0600 file; an existing `out` is never replaced.
pub(crate) fn export_to(data_dir: &Path, out: &Path, with_secrets: bool) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let text = export(data_dir, with_secrets)
        .map_err(|error| anyhow::anyhow!("configuration db: {error}"))?;
    let name = out
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} names no file", out.display()))?;
    let mut staged = name.to_owned();
    staged.push(format!(".{}.tmp", std::process::id()));
    let staged = out.with_file_name(staged);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&staged)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", staged.display()))?;
    // A hard link publishes the complete file and, unlike rename, never replaces `out`.
    let published = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::hard_link(&staged, out));
    let _ = std::fs::remove_file(&staged);
    published.map_err(|error| anyhow::anyhow!("write {}: {error}", out.display()))?;
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn head_and_parent(connection: &Connection) -> Result<Option<(i64, Option<i64>)>, StoreError> {
    let Some(number) = head(connection)? else {
        return Ok(None);
    };
    let parent = connection
        .query_row(
            "SELECT parent FROM revision WHERE number = ?1",
            [number],
            |row| row.get(0),
        )
        .map_err(sql)?;
    Ok(Some((number, parent)))
}

fn head(connection: &Connection) -> Result<Option<i64>, StoreError> {
    connection
        .query_row("SELECT active FROM head WHERE id = 1", [], |row| row.get(0))
        .optional()
        .map_err(sql)
}

fn active_revision(
    connection: &Connection,
) -> Result<Option<(i64, PathBuf, Revision)>, StoreError> {
    let Some(number) = head(connection)? else {
        return Ok(None);
    };
    let (root, revision) = revision(connection, number)?.ok_or(StoreError::Corrupt)?;
    Ok(Some((number, root, revision)))
}

fn revision(
    connection: &Connection,
    number: i64,
) -> Result<Option<(PathBuf, Revision)>, StoreError> {
    let Some((root, sources, content_sha256, bytes)): Option<(String, String, String, i64)> =
        connection
            .query_row(
                "SELECT root, sources, content_sha256, bytes FROM revision WHERE number = ?1",
                [number],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sql)?
    else {
        return Ok(None);
    };
    let root = lexical(Path::new(&root)).map_err(|_| StoreError::Corrupt)?;
    if digest(sources.as_bytes()) != content_sha256 {
        return Err(StoreError::Corrupt);
    }
    let sources: Vec<StoredSource> =
        serde_json::from_str(&sources).map_err(|_| StoreError::Corrupt)?;
    let total: usize = sources.iter().map(|source| source.content.len()).sum();
    if sources.is_empty()
        || sources.len() > MAX_SOURCES
        || i64::try_from(total).ok() != Some(bytes)
        || sources.iter().enumerate().any(|(index, source)| {
            valid_name(Path::new(&source.name)).is_err()
                || digest(source.content.as_bytes()) != source.sha256
                || match source.parent {
                    None => index != 0,
                    Some(parent) => parent >= index,
                }
        })
    {
        return Err(StoreError::Corrupt);
    }
    Ok(Some((root, Revision { sources })))
}

fn listener_secrets(connection: &Connection) -> Result<StoredSecrets, StoreError> {
    let mut secrets = StoredSecrets::default();
    let mut statement = connection
        .prepare("SELECT api, value FROM listener_secret")
        .map_err(sql)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sql)?;
    for row in rows {
        let (api, value) = row.map_err(sql)?;
        match api.as_str() {
            "native_api" => secrets.native_api = value,
            "clash_api" => secrets.clash_api = value,
            _ => return Err(StoreError::Corrupt),
        }
    }
    Ok(secrets)
}

fn insert(
    connection: &Connection,
    parent: Option<i64>,
    root: &Path,
    sources: &[StoredSource],
    principal: &str,
    origin: Origin,
) -> Result<i64, StoreError> {
    let text = serde_json::to_string(sources).map_err(|_| StoreError::Invalid)?;
    let bytes: usize = sources.iter().map(|source| source.content.len()).sum();
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64);
    connection
        .execute(
            "INSERT INTO revision (parent, created_at, principal, origin, root, sources, content_sha256, bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                parent,
                created_at,
                principal,
                origin.as_str(),
                root.to_str().ok_or(StoreError::Invalid)?,
                text,
                digest(text.as_bytes()),
                i64::try_from(bytes).map_err(|_| StoreError::Invalid)?,
            ],
        )
        .map_err(sql)?;
    Ok(connection.last_insert_rowid())
}

/// Oldest first, until at most `MAX_REVISIONS` and `MAX_RETAINED_BYTES` of stored JSON remain.
fn prune(connection: &Connection, active: i64) -> rusqlite::Result<()> {
    let rows: Vec<(i64, i64)> = connection
        .prepare("SELECT number, octet_length(sources) FROM revision ORDER BY number DESC")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let (mut kept, mut total, mut full) = (0usize, 0usize, false);
    for (number, bytes) in rows {
        let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
        full |= kept >= MAX_REVISIONS || total.saturating_add(bytes) > MAX_RETAINED_BYTES;
        if full && number != active {
            connection.execute("DELETE FROM revision WHERE number = ?1", [number])?;
        } else {
            kept += 1;
            total = total.saturating_add(bytes);
        }
    }
    Ok(())
}

/// The length `insert` will store, without building the text.
fn json_len(sources: &[StoredSource]) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    match serde_json::to_writer(&mut count, sources) {
        Ok(()) => count.0,
        Err(_) => usize::MAX,
    }
}

fn valid_name(name: &Path) -> Result<(), StoreError> {
    let text = name.to_str().ok_or(StoreError::Invalid)?;
    if text.is_empty()
        || text.len() > MAX_NAME_BYTES
        || text.contains('\0')
        || name.components().collect::<PathBuf>() != name
        || name
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || name.extension().and_then(|value| value.to_str()) != Some("dae")
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn lexical(path: &Path) -> Result<PathBuf, StoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(StoreError::Invalid);
    }
    Ok(path.components().collect())
}

fn sql(error: rusqlite::Error) -> StoreError {
    crate::state::sql(error).into()
}

fn write_sql(error: rusqlite::Error) -> WriteError {
    log_sql(&error);
    WriteError::Unavailable
}

fn store_unavailable() -> DetailedConfigError {
    DetailedConfigError::new(
        ErrorCategory::Io(std::io::ErrorKind::Other),
        "config-store-unavailable",
        DiagnosticSources::new(None).root(),
        SettingPath::new("config"),
        "configuration store is unavailable",
    )
}

#[cfg(test)]
mod tests;
