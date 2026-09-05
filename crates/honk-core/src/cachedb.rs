//! Persistent cache database (sing-box `cache_file` equivalent).
//!
//! Stores selector choices, clash mode, and (optionally, via
//! `cache_file.store_dns`) DNS answers across honk-core restarts.
//! Backed by SQLite in WAL mode. On open, if the file fails to open or
//! does not pass `PRAGMA quick_check`, the corrupt file is renamed to
//! `<name>.corrupt-<unix_ts>` and a fresh database is created (sing-box
//! `resetDB` semantics). Write failures are logged and never fatal.
//!
//! `cache_id` namespaces all keys: when non-empty, every key is stored as
//! `"{cache_id}:{key}"` so multiple router instances can share one file.
//! The prefix is an internal detail; the public API takes plain keys.

use honk_config::experimental::CacheFileConfig;
use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

#[derive(Debug, thiserror::Error)]
pub enum CacheDbError {
    #[error("cache.db connection lock is poisoned")]
    LockPoisoned,
    #[error("cache.db operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
}
#[derive(Clone)]
struct PendingWrite {
    sequence: u64,
    value: Option<String>,
}

fn flush_pending_writes(
    pending: &Mutex<HashMap<String, PendingWrite>>,
    writer: &mpsc::SyncSender<Write>,
) -> Result<(), CacheDbError> {
    let snapshot = pending
        .lock()
        .map_err(|_| CacheDbError::LockPoisoned)?
        .iter()
        .map(|(key, value)| (key.clone(), value.sequence))
        .collect::<HashMap<_, _>>();
    if snapshot.is_empty() {
        return Ok(());
    }
    let (ack, result) = mpsc::channel();
    writer
        .send(Write::Barrier(ack))
        .map_err(|_| CacheDbError::LockPoisoned)?;
    result.recv().map_err(|_| CacheDbError::LockPoisoned)??;
    pending
        .lock()
        .map_err(|_| CacheDbError::LockPoisoned)?
        .retain(|key, value| snapshot.get(key) != Some(&value.sequence));
    Ok(())
}

fn run_writer(mut conn: Connection, receiver: mpsc::Receiver<Write>) {
    let mut latest = HashMap::<String, String>::new();
    fn flush(
        conn: &mut Connection,
        latest: &mut HashMap<String, String>,
    ) -> Result<(), rusqlite::Error> {
        if latest.is_empty() {
            return Ok(());
        }
        let transaction = conn.transaction()?;
        let mut statement =
            transaction.prepare("INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)")?;
        for (key, value) in latest.iter() {
            statement.execute(params![key, value])?;
        }
        drop(statement);
        transaction.commit()?;
        latest.clear();
        Ok(())
    }
    while let Ok(write) = receiver.recv() {
        match write {
            Write::Set(key, value) => {
                latest.insert(key, value);
                if latest.len() >= 64
                    && let Err(error) = flush(&mut conn, &mut latest)
                {
                    tracing::warn!(%error, "cache.db writer batch failed");
                }
            }
            Write::Remove(key) => {
                if let Err(error) = flush(&mut conn, &mut latest).and_then(|_| {
                    conn.execute("DELETE FROM kv WHERE key = ?1", params![key])
                        .map(|_| ())
                }) {
                    tracing::warn!(%error, "cache.db remove failed");
                }
            }
            Write::FlushPrefix(prefix, ack) => {
                let result = flush(&mut conn, &mut latest)
                    .and_then(|_| {
                        conn.execute(
                            "DELETE FROM kv WHERE key LIKE ?1 ESCAPE '\\'",
                            params![format!("{prefix}%")],
                        )
                        .map(|_| ())
                    })
                    .map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            Write::Barrier(ack) => {
                let result = flush(&mut conn, &mut latest).map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            Write::DnsV2(entries, ack) => {
                let result = (|| -> Result<(), rusqlite::Error> {
                    flush(&mut conn, &mut latest)?;
                    let transaction = conn.transaction()?;
                    let mut statement = transaction
                        .prepare("INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)")?;
                    for (key, value) in entries {
                        statement.execute(params![key, value])?;
                    }
                    drop(statement);
                    transaction.commit()
                })()
                .map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            Write::FlushDns(legacy, v2, ack) => {
                let result = flush(&mut conn, &mut latest).and_then(|_| conn.execute("DELETE FROM kv WHERE key LIKE ?1 ESCAPE '\\' OR key LIKE ?2 ESCAPE '\\'", params![format!("{legacy}%"), format!("{v2}%")]).map(|_| ())).map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            #[cfg(test)]
            Write::SetQueryOnly(enabled, ack) => {
                let result = conn
                    .pragma_update(None, "query_only", enabled)
                    .map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            #[cfg(test)]
            Write::Block(entered, release) => {
                let _ = entered.send(());
                let _ = release.recv();
            }
        }
    }
    if let Err(error) = flush(&mut conn, &mut latest) {
        tracing::warn!(%error, "cache.db writer final flush failed");
    }
}

enum Write {
    Set(String, String),
    Remove(String),
    FlushPrefix(String, mpsc::Sender<Result<(), CacheDbError>>),
    Barrier(mpsc::Sender<Result<(), CacheDbError>>),
    DnsV2(
        Vec<(String, Vec<u8>)>,
        mpsc::Sender<Result<(), CacheDbError>>,
    ),
    FlushDns(String, String, mpsc::Sender<Result<(), CacheDbError>>),
    #[cfg(test)]
    SetQueryOnly(bool, mpsc::Sender<Result<(), CacheDbError>>),
    #[cfg(test)]
    Block(mpsc::Sender<()>, mpsc::Receiver<()>),
}

#[cfg(test)]
pub(crate) struct CacheDbWriterGuard {
    release: mpsc::Sender<()>,
}

#[cfg(test)]
impl Drop for CacheDbWriterGuard {
    fn drop(&mut self) {
        let _ = self.release.send(());
    }
}

pub struct CacheDb {
    /// Read-only connection. Writes are serialized by `writer`, so readers
    /// never wait behind an arbitrary write batch while holding this lock.
    conn: Mutex<Connection>,
    /// Latest asynchronous point writes, used by point reads until the writer
    /// has durably folded them into SQLite.
    pending: Arc<Mutex<HashMap<String, PendingWrite>>>,
    writer: mpsc::SyncSender<Write>,
    next_sequence: std::sync::atomic::AtomicU64,
    prefix: String,
    #[cfg(test)]
    write_attempted: std::sync::atomic::AtomicBool,
}

impl Drop for CacheDb {
    fn drop(&mut self) {
        if let Err(error) = self.flush_pending() {
            tracing::warn!(%error, "cache.db final point-write flush failed");
        }
    }
}

impl CacheDb {
    /// Open (or create) the cache database at the configured path.
    /// Returns `None` when `config.enabled` is false, or when the database
    /// cannot be opened even after a corruption reset.
    pub fn open(config: &CacheFileConfig) -> Option<Self> {
        Self::open_with_config_dir(config, None)
    }

    /// Open a cache database while preserving an existing path resolved
    /// relative to the legacy configuration directory.
    pub fn open_with_config_dir(
        config: &CacheFileConfig,
        legacy_config_dir: Option<&Path>,
    ) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let path = resolve_path(&config.path, legacy_config_dir);
        let prefix = if config.cache_id.is_empty() {
            String::new()
        } else {
            format!("{}:", config.cache_id)
        };

        let conn = match open_and_check(&path) {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(
                    "cache.db at {} failed open/integrity check ({}); resetting",
                    path.display(),
                    e
                );
                reset_corrupt(&path);
                match open_and_check(&path) {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!("cache.db reset at {} failed: {}", path.display(), e);
                        return None;
                    }
                }
            }
        };

        if let Err(e) = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');",
        ) {
            tracing::warn!("cache.db schema init failed: {}", e);
            return None;
        }

        let reader = match open_and_check(&path) {
            Ok(conn) => conn,
            Err(error) => {
                tracing::warn!(%error, "cache.db reader connection failed");
                return None;
            }
        };
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (writer, receiver) = mpsc::sync_channel(1024);
        std::thread::Builder::new()
            .name("honk-cache-db-writer".into())
            .spawn(move || run_writer(conn, receiver))
            .map_err(|error| tracing::warn!(%error, "cache.db writer spawn failed"))
            .ok()?;
        let flush_pending = Arc::downgrade(&pending);
        let flush_writer = writer.clone();
        std::thread::Builder::new()
            .name("honk-cache-db-flusher".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    let Some(pending) = flush_pending.upgrade() else {
                        break;
                    };
                    if let Err(error) = flush_pending_writes(&pending, &flush_writer) {
                        tracing::warn!(%error, "cache.db periodic point-write flush failed");
                    }
                }
            })
            .map_err(|error| tracing::warn!(%error, "cache.db flusher spawn failed"))
            .ok()?;
        Some(Self {
            conn: Mutex::new(reader),
            pending,
            writer,
            next_sequence: std::sync::atomic::AtomicU64::new(1),
            prefix,
            #[cfg(test)]
            write_attempted: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Wrap a plain key with the `cache_id` namespace prefix.
    fn wrap(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}{}", self.prefix, key)
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let key = self.wrap(key);
        if let Some(value) = self.pending.lock().ok()?.get(&key) {
            return value.value.clone();
        }
        let conn = self.conn.lock().ok()?;
        conn.query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .ok()
    }
    pub fn set(&self, key: &str, value: &str) {
        let key = self.wrap(key);
        let sequence = self
            .next_sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let value = value.to_owned();
        let Ok(mut pending) = self.pending.lock() else {
            tracing::warn!("cache.db pending-write lock poisoned");
            return;
        };
        let previous = pending.insert(
            key.clone(),
            PendingWrite {
                sequence,
                value: Some(value.clone()),
            },
        );
        if let Err(error) = self.writer.send(Write::Set(key.clone(), value)) {
            match previous {
                Some(value) => {
                    pending.insert(key, value);
                }
                None => {
                    pending.remove(&key);
                }
            }
            tracing::warn!(%error, "cache.db writer closed; point write rejected");
        }
    }

    pub fn remove(&self, key: &str) {
        let key = self.wrap(key);
        let sequence = self
            .next_sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Ok(mut pending) = self.pending.lock() else {
            tracing::warn!("cache.db pending-write lock poisoned");
            return;
        };
        let previous = pending.insert(
            key.clone(),
            PendingWrite {
                sequence,
                value: None,
            },
        );
        if let Err(error) = self.writer.send(Write::Remove(key.clone())) {
            match previous {
                Some(value) => {
                    pending.insert(key, value);
                }
                None => {
                    pending.remove(&key);
                }
            }
            tracing::warn!(%error, "cache.db writer closed; remove rejected");
        }
    }

    fn flush_pending(&self) -> Result<(), CacheDbError> {
        flush_pending_writes(&self.pending, &self.writer)
    }

    /// Delete all keys starting with `prefix` (after namespacing).
    pub fn flush_prefix(&self, prefix: &str) {
        let prefix = self.wrap(prefix);
        let Ok(mut pending) = self.pending.lock() else {
            tracing::warn!("cache.db pending-write lock poisoned");
            return;
        };
        let (ack, result) = mpsc::channel();
        let flushed = self
            .writer
            .send(Write::FlushPrefix(prefix.clone(), ack))
            .map_err(|_| CacheDbError::LockPoisoned)
            .and_then(|_| result.recv().map_err(|_| CacheDbError::LockPoisoned))
            .and_then(|result| result);
        match flushed {
            Ok(()) => pending.retain(|key, _| !key.starts_with(&prefix)),
            Err(error) => tracing::warn!(%error, "cache.db prefix flush failed"),
        }
    }

    pub(crate) fn write_dns_v2(&self, entries: &[(String, Vec<u8>)]) -> Result<(), CacheDbError> {
        if entries.is_empty() {
            return Ok(());
        }
        #[cfg(test)]
        self.write_attempted
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (ack, result) = mpsc::channel();
        self.writer
            .send(Write::DnsV2(
                entries
                    .iter()
                    .map(|(suffix, value)| (self.wrap(&format!("dns:v2:{suffix}")), value.clone()))
                    .collect(),
                ack,
            ))
            .map_err(|_| CacheDbError::LockPoisoned)?;
        result.recv().map_err(|_| CacheDbError::LockPoisoned)?
    }

    pub(crate) fn load_dns_v2(&self) -> Result<Vec<(String, Vec<u8>)>, CacheDbError> {
        let prefix = self.wrap("dns:v2:");
        let escaped = escape_like_prefix(&prefix);
        let conn = self.conn.lock().map_err(|_| CacheDbError::LockPoisoned)?;
        let mut statement =
            conn.prepare("SELECT key, value FROM kv WHERE key LIKE ?1 ESCAPE '\\'")?;
        let rows = statement.query_map(params![format!("{escaped}%")], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|row| {
            let (key, value) = row?;
            let suffix = key
                .strip_prefix(&prefix)
                .ok_or(rusqlite::Error::InvalidQuery)?
                .to_string();
            Ok((suffix, value))
        })
        .collect::<Result<Vec<_>, rusqlite::Error>>()
        .map_err(CacheDbError::from)
    }

    pub(crate) fn flush_dns_namespaces(&self) -> Result<(), CacheDbError> {
        let legacy = self.wrap("dns:");
        let v2 = self.wrap("dns:v2:");
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| CacheDbError::LockPoisoned)?;
        let (ack, result) = mpsc::channel();
        self.writer
            .send(Write::FlushDns(
                escape_like_prefix(&legacy),
                escape_like_prefix(&v2),
                ack,
            ))
            .map_err(|_| CacheDbError::LockPoisoned)?;
        result.recv().map_err(|_| CacheDbError::LockPoisoned)??;
        pending.retain(|key, _| !key.starts_with(&legacy));
        Ok(())
    }

    pub fn load_selector_choice(&self, group: &str) -> Option<String> {
        self.get(&format!("selector:{}", group))
    }

    pub fn save_selector_choice(&self, group: &str, node: &str) {
        self.set(&format!("selector:{}", group), node);
    }

    pub fn load_clash_mode(&self) -> Option<String> {
        self.get("clash_mode")
    }

    pub fn save_clash_mode(&self, mode: &str) {
        self.set("clash_mode", mode);
    }

    /// Persist a node's last real delay sample under `delay:{node}`
    /// (sing-box URLTest history storage parity: selections formed right
    /// after a restart must not start cold).
    pub fn save_delay_sample(&self, node: &str, delay_ms: u64, measured_at_unix: u64) {
        let value = serde_json::json!({
            "delay_ms": delay_ms,
            "measured_at": measured_at_unix,
        });
        self.set(&format!("delay:{}", node), &value.to_string());
    }

    /// Load every persisted delay sample no older than `max_age_secs`
    /// relative to `now_unix`. Stale or malformed entries are skipped and
    /// lazily deleted. Returns `(node, delay_ms, measured_at_unix)`.
    pub fn load_delay_samples(&self, now_unix: u64, max_age_secs: u64) -> Vec<(String, u64, u64)> {
        if let Err(error) = self.flush_pending() {
            tracing::warn!(%error, "cache.db delay scan flush failed");
        }
        let prefix = self.wrap("delay:");
        let escaped = prefix
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let rows: Vec<(String, String)> = {
            let Ok(conn) = self.conn.lock() else {
                return Vec::new();
            };
            let mut stmt =
                match conn.prepare("SELECT key, value FROM kv WHERE key LIKE ?1 ESCAPE '\\'") {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        tracing::warn!("cache.db load_delay_samples prepare failed: {}", e);
                        return Vec::new();
                    }
                };
            match stmt
                .query_map(params![format!("{}%", escaped)], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!("cache.db load_delay_samples query failed: {}", e);
                    return Vec::new();
                }
            }
        };
        let mut out = Vec::new();
        for (key, value) in rows {
            let node = key[prefix.len()..].to_string();
            let parsed = serde_json::from_str::<serde_json::Value>(&value).ok();
            let (delay_ms, measured_at) = parsed
                .as_ref()
                .and_then(|v| {
                    Some((
                        v.get("delay_ms")?.as_u64()?,
                        v.get("measured_at")?.as_u64()?,
                    ))
                })
                .unwrap_or((0, 0));
            if measured_at == 0
                || delay_ms == 0
                || now_unix.saturating_sub(measured_at) > max_age_secs
            {
                self.remove(&format!("delay:{}", node));
                continue;
            }
            out.push((node, delay_ms, measured_at));
        }
        out
    }

    /// Persist one DNS answer under `dns:{name}:{qtype}`. `answer_json` is
    /// the opaque payload produced by the DNS layer (a JSON document);
    /// `expire_at_unix` is the absolute expiry as seconds since UNIX epoch.
    pub fn save_dns_answer(&self, name: &str, qtype: u16, answer_json: &str, expire_at_unix: u64) {
        // Embed the answer payload as nested JSON when it parses; otherwise
        // keep it as a plain string so no data is ever dropped.
        let answer = serde_json::from_str::<serde_json::Value>(answer_json)
            .unwrap_or_else(|_| serde_json::Value::String(answer_json.to_string()));
        let value = serde_json::json!({
            "expire_at": expire_at_unix,
            "answer": answer,
        });
        self.set(&format!("dns:{}:{}", name, qtype), &value.to_string());
    }

    /// Load every persisted DNS answer that is still fresh at `now_unix`.
    /// Expired (or malformed) entries are skipped and lazily deleted.
    pub fn load_dns_answers(&self, now_unix: u64) -> Vec<PersistedDnsAnswer> {
        if let Err(error) = self.flush_pending() {
            tracing::warn!(%error, "cache.db DNS scan flush failed");
        }
        let prefix = self.wrap("dns:");
        let v2_prefix = self.wrap("dns:v2:");
        let escaped = prefix
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let rows: Vec<(String, String)> = {
            let Ok(conn) = self.conn.lock() else {
                return Vec::new();
            };
            let mut stmt = match conn.prepare(
                "SELECT key, value FROM kv
                 WHERE key LIKE ?1 ESCAPE '\\' AND key NOT LIKE ?2 ESCAPE '\\'",
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    tracing::warn!("cache.db load_dns_answers prepare failed: {}", e);
                    return Vec::new();
                }
            };
            match stmt
                .query_map(
                    params![
                        format!("{}%", escaped),
                        format!("{}%", escape_like_prefix(&v2_prefix))
                    ],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!("cache.db load_dns_answers query failed: {}", e);
                    return Vec::new();
                }
            }
        };

        let mut out = Vec::new();
        for (wrapped_key, value) in rows {
            let key = wrapped_key
                .strip_prefix(&self.prefix)
                .unwrap_or(&wrapped_key);
            let Some(rest) = key.strip_prefix("dns:") else {
                continue;
            };
            if rest.starts_with("v2:") {
                continue;
            }
            // The key is `dns:{name}:{qtype}`; DNS names never contain ':'.
            let Some((name, qtype)) = rest.rsplit_once(':') else {
                continue;
            };
            let Ok(qtype) = qtype.parse::<u16>() else {
                continue;
            };
            let parsed = serde_json::from_str::<serde_json::Value>(&value).ok();
            let expire_at = parsed
                .as_ref()
                .and_then(|v| v.get("expire_at"))
                .and_then(|v| v.as_u64());
            let answer_json = parsed.as_ref().and_then(|v| v.get("answer")).and_then(|v| {
                if v.is_string() {
                    v.as_str().map(str::to_string)
                } else {
                    serde_json::to_string(v).ok()
                }
            });
            let (Some(expire_at), Some(answer_json)) = (expire_at, answer_json) else {
                // Malformed row — drop it so it does not linger forever.
                self.remove(key);
                continue;
            };
            if expire_at <= now_unix {
                // Expired — lazily delete (sing-box cache_file semantics).
                self.remove(key);
                continue;
            }
            out.push(PersistedDnsAnswer {
                name: name.to_string(),
                qtype,
                answer_json,
                expire_at_unix: expire_at,
            });
        }
        out
    }

    /// Delete all persisted DNS answers (`dns:` prefix).
    pub fn flush_dns(&self) {
        if let Err(error) = self.flush_dns_namespaces() {
            tracing::warn!(%error, "cache.db DNS flush failed");
        }
    }

    #[cfg(test)]
    pub(crate) fn set_query_only_for_test(&self, enabled: bool) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.pragma_update(None, "query_only", enabled);
        }
        let (ack, result) = mpsc::channel();
        if self.writer.send(Write::SetQueryOnly(enabled, ack)).is_ok() {
            let _ = result.recv();
        }
    }

    #[cfg(test)]
    pub(crate) fn lock_for_test(&self) -> CacheDbWriterGuard {
        let (entered, ready) = mpsc::channel();
        let (release, released) = mpsc::channel();
        self.writer
            .send(Write::Block(entered, released))
            .expect("cache.db writer available");
        ready.recv().expect("cache.db writer blocked");
        CacheDbWriterGuard { release }
    }

    #[cfg(test)]
    pub(crate) fn write_attempted_for_test(&self) -> bool {
        self.write_attempted
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A DNS answer restored from the persistent cache (`store_dns`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedDnsAnswer {
    pub name: String,
    pub qtype: u16,
    /// Opaque payload as produced by `save_dns_answer` (JSON document).
    pub answer_json: String,
    pub expire_at_unix: u64,
}

/// Open the database, apply pragmas, and verify integrity via quick_check.
fn open_and_check(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA busy_timeout=1000;
         PRAGMA synchronous=NORMAL;",
    )
    .map_err(|e| e.to_string())?;
    let ok: String = conn
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if ok != "ok" {
        return Err(format!("quick_check returned '{}'", ok));
    }
    Ok(conn)
}

fn escape_like_prefix(prefix: &str) -> String {
    prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Rename a corrupt database file aside (`<name>.corrupt-<unix_ts>`) and
/// remove stale WAL/SHM sidecars so a fresh database can be created.
fn reset_corrupt(path: &Path) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("cache.db");
    let backup = path.with_file_name(format!("{}.corrupt-{}", name, ts));
    if let Err(e) = std::fs::rename(path, &backup) {
        tracing::warn!(
            "failed to rename corrupt cache.db {} -> {}: {}",
            path.display(),
            backup.display(),
            e
        );
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
        if sidecar.exists() {
            let _ = std::fs::remove_file(sidecar);
        }
    }
}

/// Resolve a cache path. Relative paths prefer the configured data directory,
/// then the previous default data directory, then an existing path under the
/// legacy configuration directory.
fn resolve_path(path: &str, legacy_config_dir: Option<&Path>) -> PathBuf {
    let configured = if path.is_empty() { "cache.db" } else { path };
    let configured_path = Path::new(configured);
    let legacy_path = legacy_cache_path(configured_path, legacy_config_dir);
    honk_config::paths::resolve_artifact_path_with_legacy(configured_path, legacy_path.as_deref())
}

fn legacy_cache_path(path: &Path, config_dir: Option<&Path>) -> Option<PathBuf> {
    if path.is_absolute() {
        None
    } else {
        Some(config_dir.map_or_else(|| path.to_path_buf(), |dir| dir.join(path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(path: &Path, cache_id: &str) -> CacheFileConfig {
        CacheFileConfig {
            enabled: true,
            path: path.to_str().unwrap().to_string(),
            cache_id: cache_id.to_string(),
            store_fakeip: false,
            store_dns: false,
        }
    }

    #[test]
    fn cache_legacy_path_uses_the_original_config_directory() {
        assert_eq!(
            legacy_cache_path(Path::new("cache.db"), Some(Path::new("/etc/honk"))),
            Some(PathBuf::from("/etc/honk/cache.db"))
        );
        assert_eq!(
            legacy_cache_path(Path::new("cache.db"), Some(Path::new(""))),
            Some(PathBuf::from("cache.db"))
        );
        assert_eq!(
            legacy_cache_path(
                Path::new("/srv/honk/cache.db"),
                Some(Path::new("/etc/honk"))
            ),
            None
        );
    }

    #[test]
    fn existing_legacy_cache_stays_available() {
        let dir = tempfile::tempdir().unwrap();
        let filename = format!("cache-{}.db", uuid::Uuid::new_v4());
        let legacy_path = dir.path().join(&filename);
        let seed = CacheDb::open(&cfg(&legacy_path, "")).unwrap();
        seed.save_selector_choice("proxy", "legacy-node");
        drop(seed);

        let config = cfg(Path::new(&filename), "");
        let db = CacheDb::open_with_config_dir(&config, Some(dir.path())).unwrap();
        assert_eq!(
            db.load_selector_choice("proxy").as_deref(),
            Some("legacy-node")
        );
    }

    #[test]
    fn basic_get_set_overwrite_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, "")).unwrap();

        assert!(db.get("missing").is_none());
        db.set("k", "v1");
        assert_eq!(db.get("k").as_deref(), Some("v1"));
        db.set("k", "v2");
        assert_eq!(db.get("k").as_deref(), Some("v2"));
        db.remove("k");
        assert!(db.get("k").is_none());
    }

    #[test]
    fn point_writes_are_latest_wins_without_blocking_readers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = std::sync::Arc::new(CacheDb::open(&cfg(&path, "")).unwrap());
        let writer = std::sync::Arc::clone(&db);
        let worker = std::thread::spawn(move || {
            for value in 0..10_000 {
                writer.set("selector:proxy", &value.to_string());
            }
        });
        for _ in 0..10_000 {
            let _ = db.get("selector:proxy");
        }
        worker.join().unwrap();
        assert_eq!(db.get("selector:proxy").as_deref(), Some("9999"));
    }

    #[test]
    fn point_save_does_not_wait_for_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = Arc::new(CacheDb::open(&cfg(&path, "")).unwrap());
        let writer_guard = db.lock_for_test();
        let (completed, completion) = mpsc::channel();
        let saving = Arc::clone(&db);
        let worker = std::thread::spawn(move || {
            saving.save_selector_choice("proxy", "node-a");
            completed.send(()).unwrap();
        });

        completion
            .recv_timeout(std::time::Duration::from_millis(100))
            .expect("point save must not wait for SQLite");
        assert_eq!(db.load_selector_choice("proxy").as_deref(), Some("node-a"));
        drop(writer_guard);
        worker.join().unwrap();
        db.flush_pending().unwrap();
    }

    #[test]
    fn periodic_flush_bounds_point_write_durability() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, "")).unwrap();
        db.set("k", "v");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let stored = db
                .conn
                .lock()
                .unwrap()
                .query_row("SELECT value FROM kv WHERE key = 'k'", [], |row| {
                    row.get::<_, String>(0)
                })
                .ok();
            if stored.as_deref() == Some("v") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "periodic flush exceeded durability bound"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn selector_choice_and_clash_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, "")).unwrap();

        assert!(db.load_selector_choice("proxy").is_none());
        db.save_selector_choice("proxy", "node-a");
        assert_eq!(db.load_selector_choice("proxy").as_deref(), Some("node-a"));

        assert!(db.load_clash_mode().is_none());
        db.save_clash_mode("Global");
        assert_eq!(db.load_clash_mode().as_deref(), Some("Global"));
    }

    #[test]
    fn cache_id_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let a = CacheDb::open(&cfg(&path, "a")).unwrap();
        let b = CacheDb::open(&cfg(&path, "b")).unwrap();

        a.save_selector_choice("proxy", "node-a");
        a.save_clash_mode("Global");

        // Different cache_id on the same file sees nothing.
        assert!(b.load_selector_choice("proxy").is_none());
        assert!(b.load_clash_mode().is_none());

        b.save_selector_choice("proxy", "node-b");
        assert_eq!(a.load_selector_choice("proxy").as_deref(), Some("node-a"));
        assert_eq!(b.load_selector_choice("proxy").as_deref(), Some("node-b"));

        // Empty cache_id is yet another (legacy) namespace.
        let plain = CacheDb::open(&cfg(&path, "")).unwrap();
        assert!(plain.load_selector_choice("proxy").is_none());
    }

    #[test]
    fn delay_sample_save_load_and_age_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, "")).unwrap();
        let now = 1_700_000_000u64;

        db.save_delay_sample("node-a", 123, now - 60);
        db.save_delay_sample("node-old", 456, now - 25 * 3600);

        let samples = db.load_delay_samples(now, 24 * 3600);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0], ("node-a".to_string(), 123, now - 60));
        // Stale entry was lazily deleted.
        assert!(
            db.load_delay_samples(now, 24 * 3600).is_empty()
                || db
                    .load_delay_samples(now, 24 * 3600)
                    .iter()
                    .all(|(n, _, _)| n != "node-old")
        );
        assert!(db.get("delay:node-old").is_none());
    }

    #[test]
    fn corrupt_file_is_backed_up_and_rebuilt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        // Garbage large enough that SQLite cannot treat it as an empty db.
        std::fs::write(&path, vec![0xABu8; 256]).unwrap();

        let db = CacheDb::open(&cfg(&path, "")).expect("open should recover");

        let backup_exists = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("cache.db.corrupt-"))
                    .unwrap_or(false)
            });
        assert!(backup_exists, "corrupt file should be renamed aside");

        db.set("k", "v");
        assert_eq!(db.get("k").as_deref(), Some("v"));
    }

    #[test]
    fn legacy_kv_schema_is_compatible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        // Build a legacy-format db by hand: only the kv table.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE kv (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
                 INSERT INTO kv (key, value) VALUES ('selector:iris', 'iris');",
            )
            .unwrap();
        }

        let db = CacheDb::open(&cfg(&path, "")).unwrap();
        assert_eq!(db.load_selector_choice("iris").as_deref(), Some("iris"));

        // The meta table is added on top without touching existing rows.
        let conn = db.conn.lock().unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
    }

    #[test]
    fn dns_answer_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, "")).unwrap();
        let now = 1_000_000u64;

        db.save_dns_answer("example.com", 1, r#"{"r":"QUJD"}"#, now + 300);
        db.save_dns_answer("example.com", 28, r#"{"r":"REVG"}"#, now + 600);

        let answers = db.load_dns_answers(now);
        assert_eq!(answers.len(), 2);
        let a = answers
            .iter()
            .find(|a| a.qtype == 1)
            .expect("A answer present");
        assert_eq!(a.name, "example.com");
        assert_eq!(a.answer_json, r#"{"r":"QUJD"}"#);
        assert_eq!(a.expire_at_unix, now + 300);
        let aaaa = answers
            .iter()
            .find(|a| a.qtype == 28)
            .expect("AAAA answer present");
        assert_eq!(aaaa.answer_json, r#"{"r":"REVG"}"#);
    }

    #[test]
    fn dns_answer_expired_is_skipped_and_lazily_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, "")).unwrap();
        let now = 1_000_000u64;

        db.save_dns_answer("stale.com", 1, r#"{"r":"QUJD"}"#, now - 1);
        db.save_dns_answer("fresh.com", 1, r#"{"r":"REVG"}"#, now + 60);

        let answers = db.load_dns_answers(now);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, "fresh.com");

        // The expired row was removed during the load.
        assert!(db.get("dns:stale.com:1").is_none());
        assert!(db.get("dns:fresh.com:1").is_some());
    }

    #[test]
    fn dns_flush_only_clears_dns_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, "")).unwrap();
        let now = 1_000_000u64;

        db.save_dns_answer("example.com", 1, r#"{"r":"QUJD"}"#, now + 300);
        db.save_selector_choice("proxy", "node-a");

        db.flush_dns();
        assert!(db.load_dns_answers(now).is_empty());
        assert_eq!(db.load_selector_choice("proxy").as_deref(), Some("node-a"));
    }

    #[test]
    fn dns_answers_respect_cache_id_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let now = 1_000_000u64;
        let a = CacheDb::open(&cfg(&path, "a")).unwrap();
        let b = CacheDb::open(&cfg(&path, "b")).unwrap();

        a.save_dns_answer("example.com", 1, r#"{"r":"QUJD"}"#, now + 300);
        assert_eq!(a.load_dns_answers(now).len(), 1);
        assert!(b.load_dns_answers(now).is_empty());

        b.flush_dns();
        assert_eq!(
            a.load_dns_answers(now).len(),
            1,
            "flushing namespace b must not touch namespace a"
        );
    }

    #[test]
    fn legacy_loader_skips_v2_blob_without_touching_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, "")).unwrap();
        let now = 1_000_000u64;
        db.save_dns_answer("legacy.example", 1, r#"{"r":"QUJD"}"#, now + 300);
        db.write_dns_v2(&[("opaque".to_string(), vec![0, 1, 2, 3])])
            .unwrap();

        let legacy = db.load_dns_answers(now);

        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].name, "legacy.example");
        assert_eq!(db.load_dns_v2().unwrap().len(), 1);
    }

    #[test]
    fn dns_flush_clears_both_namespaces_for_current_cache_id_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let now = 1_000_000u64;
        let first = CacheDb::open(&cfg(&path, "first")).unwrap();
        let second = CacheDb::open(&cfg(&path, "second")).unwrap();
        for db in [&first, &second] {
            db.save_dns_answer("example.com", 1, r#"{"r":"QUJD"}"#, now + 300);
            db.write_dns_v2(&[("opaque".to_string(), vec![0, 1, 2, 3])])
                .unwrap();
            db.save_selector_choice("proxy", "node-a");
        }

        first.flush_dns_namespaces().unwrap();

        assert!(first.load_dns_answers(now).is_empty());
        assert!(first.load_dns_v2().unwrap().is_empty());
        assert_eq!(
            first.load_selector_choice("proxy").as_deref(),
            Some("node-a")
        );
        assert_eq!(second.load_dns_answers(now).len(), 1);
        assert_eq!(second.load_dns_v2().unwrap().len(), 1);
        assert_eq!(
            second.load_selector_choice("proxy").as_deref(),
            Some("node-a")
        );
    }

    #[test]
    fn v2_blob_keeps_schema_version_and_non_dns_rows_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, "")).unwrap();
        db.save_selector_choice("proxy", "node-a");
        db.write_dns_v2(&[("opaque".to_string(), vec![0, 255, 1])])
            .unwrap();

        let conn = db.conn.lock().unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let selector: String = conn
            .query_row(
                "SELECT value FROM kv WHERE key = 'selector:proxy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let value_type: String = conn
            .query_row(
                "SELECT typeof(value) FROM kv WHERE key = 'dns:v2:opaque'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
        assert_eq!(selector, "node-a");
        assert_eq!(value_type, "blob");
    }
}
