//! The state database, `<data_dir>/state/honk.db`: one private SQLite file for
//! everything honk persists.
//!
//! Strict tables hold what the operator cannot regenerate and are written with
//! `synchronous = FULL`; cache tables are written by other connections with
//! `NORMAL`. Both share one `max_page_count` ceiling.

pub mod cache;
pub(crate) mod import;
pub(crate) mod startup;

use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg, OFlag, open, openat};
use nix::sys::stat::{Mode, mkdirat};
use parking_lot::{Mutex, MutexGuard};
use rusqlite::{Connection, OpenFlags, OptionalExtension as _, TransactionBehavior};

pub(crate) const STATE_DIR: &str = "state";
pub(crate) const DB_FILE: &str = "honk.db";
pub(crate) const APPLICATION_ID: i64 = 0x686f_6e6b;
pub(crate) const SCHEMA_VERSION: i64 = 2;
const PAGE_SIZE: i64 = 4096;
/// 112 MiB of 4 KiB pages.
const MAX_PAGE_COUNT: i64 = 28672;
/// 24 MiB that cache writes leave free: a 16 MiB revision inserted before
/// pruning plus an 8 MiB replaced subscription body.
const STRICT_HEADROOM_PAGES: i64 = 6144;
/// Free pages one `incremental_vacuum` returns to the filesystem (1 MiB), so a
/// tick after a large deletion does not rewrite the whole free list at once.
pub(crate) const VACUUM_PAGES: i64 = 256;
const CACHE_KIB: i64 = 256;
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(2000);

const DIR_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

const SCHEMA: &str = "
CREATE TABLE revision (
  number INTEGER PRIMARY KEY AUTOINCREMENT,
  parent INTEGER REFERENCES revision(number) ON DELETE SET NULL,
  created_at INTEGER NOT NULL, principal TEXT NOT NULL,
  origin TEXT NOT NULL CHECK (origin IN ('import','write','activate')),
  root TEXT NOT NULL,
  sources TEXT NOT NULL,
  content_sha256 TEXT NOT NULL, bytes INTEGER NOT NULL);
CREATE TABLE head (id INTEGER PRIMARY KEY CHECK (id=1), active INTEGER NOT NULL REFERENCES revision(number));
CREATE TABLE listener_secret (api TEXT PRIMARY KEY CHECK (api IN ('native_api','clash_api')), value TEXT NOT NULL);
CREATE TABLE admin (id INTEGER PRIMARY KEY CHECK (id=1), record TEXT NOT NULL CHECK (length(record) <= 4096));
CREATE TABLE subscription_body (key TEXT PRIMARY KEY, fetched_at INTEGER NOT NULL,
  body BLOB NOT NULL CHECK (length(body) <= 8388608));
-- One row per legacy file ever imported, keyed by its configured path: bounded by
-- the paths an operator configures. A row outlives its file so a file an older
-- binary recreates is never imported again.
CREATE TABLE legacy_import (source TEXT PRIMARY KEY, done_at INTEGER NOT NULL);
CREATE TABLE selector (grp TEXT NOT NULL, network TEXT NOT NULL CHECK (network IN ('tcp','udp')),
  member TEXT NOT NULL, PRIMARY KEY (grp, network)) WITHOUT ROWID;
CREATE TABLE delay_sample (node TEXT PRIMARY KEY, delay_ms INTEGER NOT NULL, measured_at INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE dns_answer (key TEXT PRIMARY KEY, expire_at INTEGER NOT NULL,
  entry BLOB NOT NULL CHECK (length(entry) <= 4096));
CREATE INDEX dns_answer_expiry ON dns_answer(expire_at);
CREATE TABLE clash_state (key TEXT PRIMARY KEY CHECK (key IN ('mode','global')), value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE geodata_settings (id INTEGER PRIMARY KEY CHECK (id=1), record TEXT NOT NULL CHECK (length(record) <= 65536));
";

/// Upgrades from older versions, in order: entry `n` takes version `n + 1` to
/// `n + 2`. Version 1 files exist both with and without `geodata_settings`,
/// so its upgrade only creates the table when it is missing.
const MIGRATIONS: [&str; 1] = [
    "CREATE TABLE IF NOT EXISTS geodata_settings (id INTEGER PRIMARY KEY CHECK (id=1), record TEXT NOT NULL CHECK (length(record) <= 65536));",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    #[error("state database is unavailable")]
    Unavailable,
    #[error("state database path is unsafe: {0}")]
    Unsafe(Refusal),
    #[error("state database is corrupt")]
    Corrupt,
    #[error("state database has a foreign application id or a newer schema")]
    Unsupported,
    #[error("state database is locked by `honk-core admin reset`")]
    Locked,
    #[error("another honk-core has the state database open")]
    InUse,
}

impl StateError {
    /// Stable cause code for the runtime degradation list.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Unsafe(_) => "unsafe",
            Self::Corrupt => "corrupt",
            Self::Unsupported => "unsupported",
            Self::Locked => "locked",
            Self::InUse => "in_use",
        }
    }
}

/// Which check refused which path. The path is relative to the data directory,
/// so the API can report the rule without the operator's local paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub(crate) target: Target,
    pub(crate) rule: Rule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    StateDir,
    Database,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    NotOwner,
    GroupOrOtherBits,
    NotDirectory,
    NotFile,
    Symlink,
    /// The file SQLite opened is not the inode that was checked.
    IdentityChanged,
}

impl Target {
    /// Relative to the data directory.
    pub(crate) fn relative_path(self) -> &'static str {
        match self {
            Self::StateDir => STATE_DIR,
            Self::Database => "state/honk.db",
        }
    }

    fn directory(self) -> bool {
        matches!(self, Self::StateDir)
    }
}

impl Rule {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotOwner => "not_owner",
            Self::GroupOrOtherBits => "group_or_other_bits",
            Self::NotDirectory => "not_directory",
            Self::NotFile => "not_file",
            Self::Symlink => "symlink",
            Self::IdentityChanged => "identity_changed",
        }
    }
}

impl Refusal {
    fn new(target: Target, rule: Rule) -> Self {
        Self { target, rule }
    }

    /// How an operator fixes `path`, the refused path, for the log.
    pub(crate) fn fix(&self, path: &Path) -> String {
        let path = path.display();
        match (self.rule, self.target.directory()) {
            (Rule::GroupOrOtherBits, true) => format!("chmod 700 {path}"),
            (Rule::GroupOrOtherBits, false) => format!("chmod 600 {path}"),
            (Rule::NotOwner, _) => format!("chown {} {path}", effective_uid()),
            (Rule::IdentityChanged, _) => format!("stop whatever replaces {path}"),
            (_, true) => format!("replace {path} with a directory"),
            (_, false) => format!("replace {path} with a regular file"),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.target.relative_path(), self.rule.as_str())
    }
}

impl From<Refusal> for StateError {
    fn from(refusal: Refusal) -> Self {
        Self::Unsafe(refusal)
    }
}

/// Connection class; it decides `synchronous` and `foreign_keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Strict,
    Cache,
}

/// The open state database. It holds a shared `flock` on `state/` for its
/// lifetime, so an exclusive lock there means no daemon has the file open.
pub struct StateDb {
    /// `/proc/self/fd`-resolved path of `honk.db`; every open compares its
    /// inode with `identity`.
    path: PathBuf,
    identity: (u64, u64),
    max_page_count: i64,
    strict: Mutex<Connection>,
    /// `subscription_body` keys of the enabled subscriptions in the published
    /// configuration; `None` until the first publication.
    enabled_subscriptions: Mutex<Option<std::collections::HashSet<String>>>,
    _lock: Flock<File>,
}

impl StateDb {
    /// Opens or creates `<data_dir>/state/honk.db` and checks its integrity.
    pub fn open(data_dir: &Path) -> Result<Self, StateError> {
        Self::open_with_ceiling(data_dir, MAX_PAGE_COUNT)
    }

    fn open_with_ceiling(data_dir: &Path, max_page_count: i64) -> Result<Self, StateError> {
        let directory = state_directory(data_dir, true, tighten)?;
        let directory = Flock::lock(directory, FlockArg::LockSharedNonblock).map_err(
            |(_, error)| match error {
                Errno::EWOULDBLOCK => StateError::Locked,
                _ => StateError::Unavailable,
            },
        )?;
        let (file, created) = match openat(
            &*directory,
            DB_FILE,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        ) {
            Ok(fd) => (File::from(fd), true),
            Err(Errno::EEXIST) => (existing(&directory)?, false),
            Err(error) => return Err(path_error(Target::Database, error)),
        };
        tighten(&file, Target::Database)?;
        let metadata = file.metadata().map_err(|_| StateError::Unavailable)?;
        let identity = (metadata.dev(), metadata.ino());
        // A newly created file is a regular descriptor: closed before SQLite
        // opens the file, while no connection of this process holds a lock.
        drop(file);
        let path = resolved(&directory)?.join(DB_FILE);
        // Checked read-only first: a read-write connection closing on a file it
        // refuses may checkpoint into it or delete its `-wal`.
        let checked = !created && check_read_only(&path, identity)?;
        let mut connection = open_checked(&path, identity, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        if !checked {
            check(&connection)?;
        }
        create_schema(&mut connection)?;
        configure(&connection, Class::Strict, max_page_count)?;
        Ok(Self {
            _lock: directory,
            path,
            identity,
            max_page_count,
            strict: Mutex::new(connection),
            enabled_subscriptions: Mutex::new(None),
        })
    }

    pub(crate) fn set_enabled_subscriptions(&self, keys: std::collections::HashSet<String>) {
        *self.enabled_subscriptions.lock() = Some(keys);
    }

    /// Pins publication until body cleanup has committed. Acquire after `strict`.
    pub(crate) fn enabled_subscriptions(
        &self,
    ) -> MutexGuard<'_, Option<std::collections::HashSet<String>>> {
        self.enabled_subscriptions.lock()
    }

    /// A new connection to the same file, configured for `class`.
    pub(crate) fn connect(&self, class: Class) -> Result<Connection, StateError> {
        let connection =
            open_checked(&self.path, self.identity, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure(&connection, class, self.max_page_count)?;
        Ok(connection)
    }

    /// Pages cache writes may fill before they prune or skip, so that a strict
    /// write always finds `STRICT_HEADROOM_PAGES` below the ceiling.
    pub(crate) fn cache_budget_pages(&self) -> i64 {
        self.max_page_count - STRICT_HEADROOM_PAGES
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(data_dir: &Path, max_page_count: i64) -> Self {
        Self::open_with_ceiling(data_dir, max_page_count).expect("state db")
    }

    /// The strict connection, `synchronous = FULL`.
    pub(crate) fn strict(&self) -> MutexGuard<'_, Connection> {
        self.strict.lock()
    }
}

/// Deletes the administrator record, for `honk-core admin reset`; `Ok(false)`
/// when there was none. Refused while any process has the db open through
/// `StateDb`, because each holds a shared lock on `state/`.
pub fn reset_admin(data_dir: &Path) -> Result<bool, StateError> {
    let directory = state_directory(data_dir, true, tighten)?;
    let directory = Flock::lock(directory, FlockArg::LockExclusiveNonblock).map_err(
        |(_, error)| match error {
            Errno::EWOULDBLOCK => StateError::InUse,
            _ => StateError::Unavailable,
        },
    )?;
    // Startup takes the shared lock before creating the db.
    match nix::sys::stat::fstatat(
        &*directory,
        DB_FILE,
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    ) {
        Err(Errno::ENOENT) => return Ok(false),
        Err(error) => return Err(path_error(Target::Database, error)),
        Ok(_) => {}
    }
    let file = existing(&directory)?;
    tighten(&file, Target::Database)?;
    let metadata = file.metadata().map_err(|_| StateError::Unavailable)?;
    drop(file);
    let path = resolved(&directory)?.join(DB_FILE);
    let connection = open_checked(
        &path,
        (metadata.dev(), metadata.ino()),
        OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?;
    check(&connection)?;
    // A first start that stopped before creating the schema left no administrator.
    let schema: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'admin'",
            [],
            |row| row.get(0),
        )
        .map_err(sql)?;
    let deleted = if schema == 0 {
        0
    } else {
        connection.execute("DELETE FROM admin", []).map_err(sql)?
    };
    Ok(deleted > 0)
}

/// Which owners of the cache tables are configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveOwners {
    /// `cache_file.enabled` not false: selectors and delays.
    pub cache: bool,
    /// `cache_file.store_dns`.
    pub dns: bool,
    /// `cache_file.enabled: true`, the native API off and the Clash API on:
    /// Clash mode and GLOBAL.
    pub clash: bool,
    /// `global.store_subscribe`: subscription bodies.
    pub subscriptions: bool,
}

/// Empties the cache tables whose owner is off, so a disabled owner leaves no
/// rows behind. Strict tables are never touched. Call with the instance lock held.
pub fn clear_inactive(state: &StateDb, owners: ActiveOwners) -> Result<(), StateError> {
    let mut tables = Vec::new();
    if !owners.cache {
        tables.extend(["selector", "delay_sample"]);
    }
    if !owners.cache || !owners.dns {
        tables.push("dns_answer");
    }
    if !owners.cache || !owners.clash {
        tables.push("clash_state");
    }
    if !owners.subscriptions {
        tables.push("subscription_body");
    }
    let mut connection = state.strict();
    let transaction = connection.transaction().map_err(sql)?;
    for table in tables {
        transaction
            .execute(&format!("DELETE FROM {table}"), [])
            .map_err(sql)?;
    }
    transaction.commit().map_err(sql)
}

/// Returns up to `VACUUM_PAGES` free pages to the filesystem. The pragma
/// frees pages as it is stepped, so it is stepped to the end.
pub(crate) fn incremental_vacuum(connection: &Connection) -> rusqlite::Result<()> {
    let mut statement =
        connection.prepare(&format!("PRAGMA incremental_vacuum({VACUUM_PAGES})"))?;
    let mut rows = statement.query([])?;
    while rows.next()?.is_some() {}
    Ok(())
}

/// Pages in use: the file's pages minus its free list.
pub(crate) fn used_pages(connection: &Connection) -> rusqlite::Result<i64> {
    connection.query_row(
        "SELECT (SELECT page_count FROM pragma_page_count()) - (SELECT freelist_count FROM pragma_freelist_count())",
        [],
        |row| row.get(0),
    )
}

/// Called with the instance lock held, after `open` found a non-strict db
/// corrupt: moves `honk.db` and its `-wal` aside as `honk.db.corrupt` and
/// `honk.db.corrupt-wal`, deletes `-shm` and creates a new file. An earlier
/// `honk.db.corrupt` is never overwritten; honk then runs without a db (`None`).
pub fn reset_corrupt(data_dir: &Path) -> Result<Option<StateDb>, StateError> {
    const CORRUPT: &str = "honk.db.corrupt";
    // Exclusive for the renames: no other process may have the file open.
    let directory = Flock::lock(
        state_directory(data_dir, false, private)?,
        FlockArg::LockExclusiveNonblock,
    )
    .map_err(|(_, error)| match error {
        Errno::EWOULDBLOCK => StateError::InUse,
        _ => StateError::Unavailable,
    })?;
    let shown = resolved(&directory)?;
    match nix::sys::stat::fstatat(
        &*directory,
        CORRUPT,
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    ) {
        Ok(_) => {
            tracing::warn!(
                database = %shown.join(DB_FILE).display(),
                earlier = %shown.join(CORRUPT).display(),
                "state database is corrupt and an earlier copy is kept; running without it"
            );
            return Ok(None);
        }
        Err(Errno::ENOENT) => {}
        Err(error) => return Err(path_error(Target::Database, error)),
    }
    // The `-wal` moves first: a crash in between must not leave it beside a new file.
    for (from, to) in [("honk.db-wal", "honk.db.corrupt-wal"), (DB_FILE, CORRUPT)] {
        match rename_noreplace(&directory, from, to) {
            Ok(()) | Err(Errno::ENOENT) => {}
            Err(Errno::EEXIST) => {
                tracing::warn!(
                    earlier = %shown.join(to).display(),
                    "state database is corrupt and an earlier copy is kept; running without it"
                );
                return Ok(None);
            }
            Err(error) => return Err(path_error(Target::Database, error)),
        }
    }
    match nix::unistd::unlinkat(
        &*directory,
        "honk.db-shm",
        nix::unistd::UnlinkatFlags::NoRemoveDir,
    ) {
        Ok(()) | Err(Errno::ENOENT) => {}
        Err(error) => return Err(path_error(Target::Database, error)),
    }
    nix::unistd::fsync(&*directory).map_err(|_| StateError::Unavailable)?;
    tracing::warn!(
        kept = %shown.join(CORRUPT).display(),
        "state database was corrupt; moved it aside and started a new one"
    );
    drop(directory);
    StateDb::open(data_dir).map(Some)
}

/// A `query_only` connection for readers such as `config export`, whether or
/// not a daemon holds the file open. It sets no pragma that writes and does not
/// checkpoint when it closes; besides the `-shm` index SQLite may create, the
/// only write it can cause is rolling back a rollback journal left by a crash.
/// Only `application_id` and `user_version` are checked, so it can read a file
/// that fails `quick_check`.
#[cfg(feature = "native-api")]
pub(crate) fn open_read_only(data_dir: &Path) -> Result<(File, Connection), StateError> {
    let directory = state_directory(data_dir, false, private)?;
    let file = existing(&directory)?;
    private(&file, Target::Database)?;
    let metadata = file.metadata().map_err(|_| StateError::Unavailable)?;
    drop(file);
    let path = resolved(&directory)?.join(DB_FILE);
    // Read-write without CREATE, so a rollback journal left by a crash can be
    // rolled back; `query_only` refuses every other write.
    let connection = open_checked(
        &path,
        (metadata.dev(), metadata.ino()),
        OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?;
    run_pragma(&connection, "PRAGMA query_only = ON")?;
    // Closing as the last connection must not checkpoint and delete the `-wal`.
    connection
        .set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .map_err(sql)?;
    if pragma(&connection, "application_id")? != APPLICATION_ID
        || !(1..=SCHEMA_VERSION).contains(&pragma(&connection, "user_version")?)
    {
        return Err(StateError::Unsupported);
    }
    Ok((directory, connection))
}

fn state_directory(
    data_dir: &Path,
    create: bool,
    check: fn(&File, Target) -> Result<(), StateError>,
) -> Result<File, StateError> {
    let parent =
        File::from(open(data_dir, DIR_FLAGS, Mode::empty()).map_err(|_| StateError::Unavailable)?);
    if create {
        match mkdirat(&parent, STATE_DIR, Mode::S_IRWXU) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(_) => return Err(StateError::Unavailable),
        }
    }
    let directory = match openat(&parent, STATE_DIR, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => File::from(fd),
        // `O_DIRECTORY | O_NOFOLLOW` also reports a symlink as `ENOTDIR`.
        Err(Errno::ENOTDIR)
            if nix::sys::stat::fstatat(
                &parent,
                STATE_DIR,
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFLNK) =>
        {
            return Err(Refusal::new(Target::StateDir, Rule::Symlink).into());
        }
        Err(error) => return Err(path_error(Target::StateDir, error)),
    };
    check(&directory, Target::StateDir)?;
    if create {
        // Also cover another creator or a previous failed sync: strict commits
        // cannot make this directory's entry durable in its parent.
        parent.sync_all().map_err(|_| StateError::Unavailable)?;
    }
    Ok(directory)
}

/// An `O_PATH` descriptor for the ownership and identity checks. Closing any
/// other descriptor of the file would drop every POSIX lock this process holds
/// on it, including those of SQLite connections already open, and another
/// process could then close as the last connection and delete the `-wal`;
/// Linux does not release them when an `O_PATH` descriptor closes.
fn existing(directory: &File) -> Result<File, StateError> {
    openat(
        directory,
        DB_FILE,
        OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| path_error(Target::Database, error))
}

// SQLite resolves `/proc/self/fd` itself, so NOFOLLOW would refuse it; the
// directory's own path is used, and the opened inode is compared instead.
fn resolved(directory: &File) -> Result<PathBuf, StateError> {
    std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .map_err(|_| StateError::Unavailable)
}

fn open_checked(
    path: &Path,
    identity: (u64, u64),
    mode: OpenFlags,
) -> Result<Connection, StateError> {
    let connection = Connection::open_with_flags(
        path,
        mode | OpenFlags::SQLITE_OPEN_NOFOLLOW | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sql)?;
    let opened = std::fs::symlink_metadata(path).map_err(|_| StateError::Unavailable)?;
    if (opened.dev(), opened.ino()) != identity {
        return Err(Refusal::new(Target::Database, Rule::IdentityChanged).into());
    }
    // Before the first read: `quick_check` would otherwise fill the default cache.
    connection.busy_timeout(BUSY_TIMEOUT).map_err(sql)?;
    run_pragma(&connection, &format!("PRAGMA cache_size = -{CACHE_KIB}"))?;
    run_pragma(&connection, "PRAGMA mmap_size = 0")?;
    Ok(connection)
}

/// `Ok(false)` when only a read-write connection can check the file: a
/// rollback journal left by a crash must be rolled back first, which a
/// read-only connection refuses with an `SQLITE_READONLY_*` code.
fn check_read_only(path: &Path, identity: (u64, u64)) -> Result<bool, StateError> {
    let hot =
        |error: &rusqlite::Error| error.sqlite_error_code() == Some(rusqlite::ErrorCode::ReadOnly);
    let connection = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Err(error) if hot(&error) => return Ok(false),
        result => result.map_err(sql)?,
    };
    let opened = std::fs::symlink_metadata(path).map_err(|_| StateError::Unavailable)?;
    if (opened.dev(), opened.ino()) != identity {
        return Err(Refusal::new(Target::Database, Rule::IdentityChanged).into());
    }
    let quick = (|| -> rusqlite::Result<String> {
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "cache_size", -CACHE_KIB)?;
        connection.pragma_update(None, "mmap_size", 0)?;
        connection.query_row("PRAGMA quick_check", [], |row| row.get(0))
    })();
    match quick {
        Err(error) if hot(&error) => Ok(false),
        result => verify(&connection, &result.map_err(sql)?).map(|()| true),
    }
}

fn check(connection: &Connection) -> Result<(), StateError> {
    connection.busy_timeout(BUSY_TIMEOUT).map_err(sql)?;
    let check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(sql)?;
    verify(connection, &check)
}

fn verify(connection: &Connection, check: &str) -> Result<(), StateError> {
    if check != "ok" {
        return Err(StateError::Corrupt);
    }
    let application_id = pragma(connection, "application_id")?;
    let version = pragma(connection, "user_version")?;
    let tables: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .map_err(sql)?;
    match (application_id, version, tables) {
        (0, 0, 0) => Ok(()),
        (APPLICATION_ID, 1..=SCHEMA_VERSION, _) => Ok(()),
        (APPLICATION_ID, 0, _) => Err(StateError::Corrupt),
        _ => Err(StateError::Unsupported),
    }
}

/// Creation-time pragmas and the schema on an empty file.
fn create_schema(connection: &mut Connection) -> Result<(), StateError> {
    match pragma(connection, "user_version")? {
        SCHEMA_VERSION => return Ok(()),
        0 => connection
            .execute_batch(&format!(
                "PRAGMA page_size = {PAGE_SIZE}; PRAGMA auto_vacuum = INCREMENTAL;"
            ))
            .map_err(sql)?,
        _ => {}
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(sql)?;
    // A concurrent start may have created the schema since the read above.
    let current = pragma(&transaction, "user_version")?;
    let application_id = pragma(&transaction, "application_id")?;
    let schema = match (application_id, current) {
        (APPLICATION_ID, SCHEMA_VERSION) => return Ok(()),
        (0, 0) => SCHEMA.to_owned(),
        (APPLICATION_ID, 1..SCHEMA_VERSION) => MIGRATIONS[current as usize - 1..].concat(),
        _ => return Err(StateError::Unsupported),
    };
    transaction
        .execute_batch(&format!(
            "{schema}PRAGMA application_id = {APPLICATION_ID};PRAGMA user_version = {SCHEMA_VERSION};"
        ))
        .map_err(sql)?;
    transaction.commit().map_err(sql)
}

/// Per-connection pragmas, set on every open.
fn configure(connection: &Connection, class: Class, max_page_count: i64) -> Result<(), StateError> {
    let mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(sql)?;
    let wal = match mode.as_str() {
        "wal" => true,
        // For example, a filesystem without shared memory.
        "delete" => {
            tracing::warn!("state database cannot use WAL; using a rollback journal");
            false
        }
        _ => return Err(StateError::Unavailable),
    };
    for statement in [
        "PRAGMA wal_autocheckpoint = 256".to_owned(),
        "PRAGMA journal_size_limit = 1048576".to_owned(),
        format!("PRAGMA max_page_count = {max_page_count}"),
    ] {
        run_pragma(connection, &statement)?;
    }
    run_pragma(
        connection,
        &format!("PRAGMA synchronous = {}", synchronous(class, wal)),
    )?;
    if class == Class::Strict {
        run_pragma(connection, "PRAGMA foreign_keys = ON")?;
    }
    Ok(())
}

/// `NORMAL` is crash-safe only under WAL; with a rollback journal a cache
/// commit, which can also move strict pages in `incremental_vacuum`, needs `FULL`.
fn synchronous(class: Class, wal: bool) -> &'static str {
    match class {
        Class::Cache if wal => "NORMAL",
        _ => "FULL",
    }
}

fn run_pragma(connection: &Connection, statement: &str) -> Result<(), StateError> {
    connection
        .query_row(statement, [], |_| Ok(()))
        .optional()
        .map(|_| ())
        .map_err(sql)
}

pub(crate) fn pragma(connection: &Connection, name: &str) -> Result<i64, StateError> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(sql)
}

/// A directory or regular file owned by the euid with no group or other bits.
fn private(file: &File, target: Target) -> Result<(), StateError> {
    match check_private(file, target)? {
        Some((rule, _)) => Err(Refusal::new(target, rule).into()),
        None => Ok(()),
    }
}

/// [`private`] for writers, where the state directory and database lose group
/// and other bits that grant no write; writable ones are refused, because
/// someone else may already have put a `-wal` beside the database. Readers such
/// as `config export` leave permissions alone.
fn tighten(file: &File, target: Target) -> Result<(), StateError> {
    let Some((rule, mode)) = check_private(file, target)? else {
        return Ok(());
    };
    if rule == Rule::GroupOrOtherBits
        && mode & 0o022 == 0
        // `fchmod` refuses the `O_PATH` descriptor of the database, while
        // `/proc/self/fd` reaches the same checked inode without a path lookup.
        && std::fs::set_permissions(
            format!("/proc/self/fd/{}", file.as_raw_fd()),
            std::fs::Permissions::from_mode(mode & 0o700),
        )
        .is_ok()
        && check_private(file, target)?.is_none()
    {
        tracing::warn!(
            path = %resolved(file).unwrap_or_default().display(),
            from = %format_args!("{mode:04o}"),
            to = %format_args!("{:04o}", mode & 0o700),
            "removed group and other permissions from the state database path"
        );
        return Ok(());
    }
    Err(Refusal::new(target, rule).into())
}

fn check_private(file: &File, target: Target) -> Result<Option<(Rule, u32)>, StateError> {
    let metadata = file.metadata().map_err(|_| StateError::Unavailable)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let rule = if metadata.file_type().is_symlink() {
        Rule::Symlink
    } else if target.directory() && !metadata.is_dir() {
        Rule::NotDirectory
    } else if !target.directory() && !metadata.is_file() {
        Rule::NotFile
    } else if metadata.uid() != effective_uid() {
        Rule::NotOwner
    } else if mode & 0o077 != 0 {
        Rule::GroupOrOtherBits
    } else {
        return Ok(None);
    };
    Ok(Some((rule, mode)))
}

pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn path_error(target: Target, error: Errno) -> StateError {
    match error {
        Errno::ELOOP => Refusal::new(target, Rule::Symlink).into(),
        Errno::ENOTDIR => Refusal::new(target, Rule::NotDirectory).into(),
        _ => StateError::Unavailable,
    }
}

/// Renames `from` to `to` within `directory`, failing with `EEXIST` rather
/// than replacing `to`. A raw `renameat2` syscall: nix wraps it only for glibc,
/// and releases also target musl.
pub(crate) fn rename_noreplace<P1, P2>(directory: &File, from: &P1, to: &P2) -> nix::Result<()>
where
    P1: ?Sized + nix::NixPath,
    P2: ?Sized + nix::NixPath,
{
    let fd = directory.as_raw_fd();
    let result = from.with_nix_path(|from| {
        to.with_nix_path(|to| {
            // SAFETY: both paths are NUL-terminated and outlive the call.
            unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    fd,
                    from.as_ptr(),
                    fd,
                    to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            }
        })
    })??;
    Errno::result(result).map(drop)
}

pub(crate) fn log_sql(error: &rusqlite::Error) {
    let code = error.sqlite_error().map(|error| error.extended_code);
    tracing::warn!(sqlite_code = ?code, "state database operation failed");
}

pub(crate) fn sql(error: rusqlite::Error) -> StateError {
    log_sql(&error);
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt) => {
            StateError::Corrupt
        }
        Some(rusqlite::ErrorCode::CannotOpen) if is_symlink_refusal(&error) => {
            Refusal::new(Target::Database, Rule::Symlink).into()
        }
        _ => StateError::Unavailable,
    }
}

fn is_symlink_refusal(error: &rusqlite::Error) -> bool {
    error
        .sqlite_error()
        .is_some_and(|error| error.extended_code == rusqlite::ffi::SQLITE_CANTOPEN_SYMLINK)
}

#[cfg(test)]
mod tests;
