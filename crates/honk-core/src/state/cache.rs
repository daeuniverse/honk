//! Runtime state in the cache tables of the state database: Selector choices,
//! delay samples, Clash mode and GLOBAL, and DNS answers.
//!
//! One writer thread owns the cache-class connection, so readers never wait
//! behind a write batch. Point writes (selectors, Clash state) are coalesced
//! in `pending` and read from there until the writer has committed them.
//! Write failures are logged and never fatal.
//!
//! Each batch checks the page budget (`StateDb::cache_budget_pages`) inside its
//! transaction: above it, DNS rows are pruned to `DNS_BUDGET_ROWS`, and if that
//! is not enough the batch is rolled back, so cache writes can never take the
//! room a strict write needs.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, mpsc};

use honk_outbound::group::{SelectionNetwork, SelectorMember};
use rusqlite::{Connection, params};

use super::{Class, StateDb, StateError};

const CHANNEL_CAPACITY: usize = 256;
/// Rows kept after each DNS batch, earliest expiry evicted first.
pub(crate) const MAX_DNS_ROWS: i64 = 4096;
const DNS_BUDGET_ROWS: i64 = 2048;
const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

#[derive(Debug, thiserror::Error)]
pub enum CacheDbError {
    #[error("state cache writer is closed")]
    Closed,
    /// Only the result code: SQLite messages can quote stored values.
    #[error("state cache operation failed with SQLite result code {0}")]
    Sqlite(i32),
}

impl From<rusqlite::Error> for CacheDbError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error.sqlite_error().map_or(-1, |error| error.extended_code))
    }
}

/// A coalesced point write.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Selector(String, &'static str),
    Clash(&'static str),
}

struct PendingWrite {
    sequence: u64,
    value: String,
}

/// `(key, expire_at_unix, entry)`.
pub(crate) type DnsRow = (String, u64, Vec<u8>);

/// What became of a DNS batch that did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsWrite {
    Written,
    /// Dropped because the db is over its cache page budget.
    Skipped,
}

/// A failed DNS batch hands its rows back to the caller.
pub(crate) type DnsWriteError = (CacheDbError, Vec<DnsRow>);

/// Deletions for one maintenance tick, in one transaction.
#[derive(Debug, Default)]
pub(crate) struct Maintenance {
    pub(crate) groups: Vec<String>,
    pub(crate) nodes: Vec<String>,
    /// Delay samples measured before this are deleted.
    pub(crate) delay_cutoff: u64,
    /// DNS rows expiring at or before this are deleted.
    pub(crate) dns_expired_at: Option<u64>,
}

enum Write {
    Set(Key, String),
    Barrier(mpsc::Sender<Result<(), CacheDbError>>),
    Delays(Vec<(String, u64, u64)>),
    DeleteDelaysBefore(u64),
    Dns(Vec<DnsRow>, mpsc::Sender<Result<DnsWrite, DnsWriteError>>),
    Maintain(Maintenance, mpsc::Sender<Result<(), CacheDbError>>),
    FlushDns(mpsc::Sender<Result<(), CacheDbError>>),
    #[cfg(any(feature = "native-api", test))]
    DeleteDns(Vec<String>, mpsc::Sender<Result<(), CacheDbError>>),
    #[cfg(test)]
    SetQueryOnly(bool, mpsc::Sender<Result<(), CacheDbError>>),
    #[cfg(test)]
    Block(mpsc::Sender<()>, mpsc::Receiver<()>),
}

fn network_name(network: SelectionNetwork) -> &'static str {
    match network {
        SelectionNetwork::Tcp => "tcp",
        SelectionNetwork::Udp => "udp",
    }
}

fn unix(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn flush_pending_writes(
    pending: &Mutex<HashMap<Key, PendingWrite>>,
    writer: &mpsc::SyncSender<Write>,
) -> Result<(), CacheDbError> {
    let snapshot = pending
        .lock()
        .map_err(|_| CacheDbError::Closed)?
        .iter()
        .map(|(key, value)| (key.clone(), value.sequence))
        .collect::<HashMap<_, _>>();
    if snapshot.is_empty() {
        return Ok(());
    }
    let (ack, result) = mpsc::channel();
    writer
        .send(Write::Barrier(ack))
        .map_err(|_| CacheDbError::Closed)?;
    result.recv().map_err(|_| CacheDbError::Closed)??;
    pending
        .lock()
        .map_err(|_| CacheDbError::Closed)?
        .retain(|key, value| snapshot.get(key) != Some(&value.sequence));
    Ok(())
}

/// Whether the batch in `transaction` leaves the db within the page budget,
/// pruning DNS rows first; the caller rolls back a batch that does not fit.
fn fits(transaction: &Connection, budget_pages: i64) -> rusqlite::Result<bool> {
    if super::used_pages(transaction)? <= budget_pages {
        return Ok(true);
    }
    transaction.execute(
        "DELETE FROM dns_answer WHERE key IN (SELECT key FROM dns_answer ORDER BY expire_at
           LIMIT max(0, (SELECT count(*) FROM dns_answer) - ?1))",
        [DNS_BUDGET_ROWS],
    )?;
    Ok(super::used_pages(transaction)? <= budget_pages)
}

struct Writer {
    connection: Connection,
    latest: HashMap<Key, String>,
    budget_pages: i64,
    /// Batches skipped for the page budget; the first one is logged.
    skipped: u64,
    // The directory lock must outlive the writer connection.
    _state: Arc<StateDb>,
}

impl Writer {
    fn skip(&mut self) {
        self.skipped = self.skipped.saturating_add(1);
        if self.skipped == 1 {
            tracing::warn!("state db is over its cache page budget; skipping cache writes");
        }
    }

    fn write_points(&mut self) -> rusqlite::Result<()> {
        if self.latest.is_empty() {
            return Ok(());
        }
        let transaction = self.connection.transaction()?;
        {
            let mut selector = transaction.prepare(
                "INSERT OR REPLACE INTO selector (grp, network, member) VALUES (?1, ?2, ?3)",
            )?;
            let mut clash = transaction
                .prepare("INSERT OR REPLACE INTO clash_state (key, value) VALUES (?1, ?2)")?;
            for (key, value) in &self.latest {
                match key {
                    Key::Selector(group, network) => {
                        selector.execute(params![group, network, value])?;
                    }
                    Key::Clash(key) => {
                        clash.execute(params![key, value])?;
                    }
                }
            }
        }
        if fits(&transaction, self.budget_pages)? {
            transaction.commit()?;
        } else {
            drop(transaction);
            self.skip();
        }
        self.latest.clear();
        Ok(())
    }

    fn write_delays(&mut self, samples: &[(String, u64, u64)]) -> rusqlite::Result<()> {
        let transaction = self.connection.transaction()?;
        {
            let mut statement = transaction.prepare(
                "INSERT OR REPLACE INTO delay_sample (node, delay_ms, measured_at)
                 VALUES (?1, ?2, ?3)",
            )?;
            for (node, delay_ms, measured_at) in samples {
                statement.execute(params![node, unix(*delay_ms), unix(*measured_at)])?;
            }
        }
        if !fits(&transaction, self.budget_pages)? {
            drop(transaction);
            self.skip();
            return Ok(());
        }
        transaction.commit()
    }

    /// Writes the batch, then evicts the earliest expiry down to `MAX_DNS_ROWS`.
    fn write_dns(&mut self, entries: &[DnsRow]) -> rusqlite::Result<DnsWrite> {
        let transaction = self.connection.transaction()?;
        {
            let mut statement = transaction.prepare(
                "INSERT OR REPLACE INTO dns_answer (key, expire_at, entry) VALUES (?1, ?2, ?3)",
            )?;
            for (key, expire_at, entry) in entries {
                statement.execute(params![key, unix(*expire_at), entry])?;
            }
        }
        transaction.execute(
            "DELETE FROM dns_answer WHERE key IN (SELECT key FROM dns_answer ORDER BY expire_at
               LIMIT max(0, (SELECT count(*) FROM dns_answer) - ?1))",
            [MAX_DNS_ROWS],
        )?;
        if !fits(&transaction, self.budget_pages)? {
            drop(transaction);
            self.skip();
            return Ok(DnsWrite::Skipped);
        }
        transaction.commit()?;
        Ok(DnsWrite::Written)
    }

    fn maintain(&mut self, work: &Maintenance) -> rusqlite::Result<()> {
        let transaction = self.connection.transaction()?;
        {
            let mut selector = transaction.prepare("DELETE FROM selector WHERE grp = ?1")?;
            for group in &work.groups {
                selector.execute([group])?;
            }
            let mut delay = transaction.prepare("DELETE FROM delay_sample WHERE node = ?1")?;
            for node in &work.nodes {
                delay.execute([node])?;
            }
        }
        transaction.execute(
            "DELETE FROM delay_sample WHERE measured_at < ?1 OR delay_ms <= 0 OR measured_at <= 0",
            [unix(work.delay_cutoff)],
        )?;
        if let Some(expired_at) = work.dns_expired_at {
            transaction.execute(
                "DELETE FROM dns_answer WHERE expire_at <= ?1",
                [unix(expired_at)],
            )?;
        }
        transaction.commit()?;
        super::incremental_vacuum(&self.connection)
    }
}

fn run_writer(mut writer: Writer, receiver: mpsc::Receiver<Write>) {
    while let Ok(write) = receiver.recv() {
        match write {
            Write::Set(key, value) => {
                writer.latest.insert(key, value);
                if writer.latest.len() >= 64
                    && let Err(error) = writer.write_points()
                {
                    tracing::warn!(error = %CacheDbError::from(error), "state cache point-write batch failed");
                }
            }
            Write::Barrier(ack) => {
                let _ = ack.send(writer.write_points().map_err(CacheDbError::from));
            }
            Write::Delays(samples) => {
                if let Err(error) = writer.write_delays(&samples) {
                    tracing::warn!(error = %CacheDbError::from(error), "state cache delay batch failed");
                }
            }
            Write::DeleteDelaysBefore(cutoff) => {
                if let Err(error) = writer.connection.execute(
                    "DELETE FROM delay_sample WHERE measured_at < ?1 OR delay_ms <= 0 OR measured_at <= 0",
                    [unix(cutoff)],
                ) {
                    tracing::warn!(error = %CacheDbError::from(error), "state cache delay prune failed");
                }
            }
            Write::Dns(entries, ack) => {
                let result = writer
                    .write_dns(&entries)
                    .map_err(|error| (CacheDbError::from(error), entries));
                let _ = ack.send(result);
            }
            Write::Maintain(work, ack) => {
                let _ = ack.send(writer.maintain(&work).map_err(CacheDbError::from));
            }
            Write::FlushDns(ack) => {
                let result = writer
                    .connection
                    .execute("DELETE FROM dns_answer", [])
                    .map(|_| ())
                    .map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            #[cfg(any(feature = "native-api", test))]
            Write::DeleteDns(keys, ack) => {
                let result = (|| -> rusqlite::Result<()> {
                    let transaction = writer.connection.transaction()?;
                    {
                        let mut statement =
                            transaction.prepare("DELETE FROM dns_answer WHERE key = ?1")?;
                        for key in &keys {
                            statement.execute([key])?;
                        }
                    }
                    transaction.commit()
                })()
                .map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            #[cfg(test)]
            Write::SetQueryOnly(enabled, ack) => {
                let result = writer
                    .connection
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
    if let Err(error) = writer.write_points() {
        tracing::warn!(error = %CacheDbError::from(error), "state cache final point-write flush failed");
    }
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

/// Wakes the flusher only while a point write is pending, so an idle cache
/// costs no timer wakeups.
#[derive(Default)]
struct FlushSignal {
    /// `(pending, closed)`.
    state: Mutex<(bool, bool)>,
    ready: std::sync::Condvar,
    #[cfg(test)]
    wakeups: std::sync::atomic::AtomicU64,
}

impl FlushSignal {
    fn notify(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.0 = true;
            self.ready.notify_one();
        }
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.1 = true;
            self.ready.notify_one();
        }
    }

    /// Blocks until a write is pending; `false` once the cache is closed.
    fn wait(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        while !state.0 && !state.1 {
            state = match self.ready.wait(state) {
                Ok(state) => state,
                Err(_) => return false,
            };
        }
        if state.1 {
            return false;
        }
        state.0 = false;
        #[cfg(test)]
        self.wakeups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }
}

pub struct CacheDb {
    /// Reader connection; writes go through `writer`.
    conn: Mutex<Connection>,
    pending: Arc<Mutex<HashMap<Key, PendingWrite>>>,
    writer: mpsc::SyncSender<Write>,
    next_sequence: std::sync::atomic::AtomicU64,
    flush: Arc<FlushSignal>,
    #[cfg(test)]
    write_attempted: std::sync::atomic::AtomicBool,
    _state: Arc<StateDb>,
}

impl Drop for CacheDb {
    fn drop(&mut self) {
        if let Err(error) = self.flush_pending() {
            tracing::warn!(%error, "state cache final point-write flush failed");
        }
        self.flush.close();
    }
}

impl CacheDb {
    /// Opens the reader and writer connections and starts the writer thread.
    pub fn open(state: Arc<StateDb>) -> Result<Self, StateError> {
        let reader = state.connect(Class::Cache)?;
        let thread = Writer {
            connection: state.connect(Class::Cache)?,
            latest: HashMap::new(),
            budget_pages: state.cache_budget_pages(),
            skipped: 0,
            _state: Arc::clone(&state),
        };
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (writer, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        std::thread::Builder::new()
            .name("honk-cache-db-writer".into())
            .spawn(move || run_writer(thread, receiver))
            .map_err(|_| StateError::Unavailable)?;
        let flush_pending = Arc::downgrade(&pending);
        let flush_writer = writer.clone();
        let flush = Arc::new(FlushSignal::default());
        let signal = Arc::clone(&flush);
        std::thread::Builder::new()
            .name("honk-cache-db-flusher".into())
            .spawn(move || {
                // A pending write reaches SQLite within `FLUSH_INTERVAL`.
                while signal.wait() {
                    std::thread::sleep(FLUSH_INTERVAL);
                    let Some(pending) = flush_pending.upgrade() else {
                        break;
                    };
                    if let Err(error) = flush_pending_writes(&pending, &flush_writer) {
                        tracing::warn!(%error, "state cache periodic point-write flush failed");
                    }
                    // Writes that arrived during the flush wait for the next round.
                    if pending.lock().is_ok_and(|pending| !pending.is_empty()) {
                        signal.notify();
                    }
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(Self {
            _state: state,
            conn: Mutex::new(reader),
            pending,
            writer,
            next_sequence: std::sync::atomic::AtomicU64::new(1),
            flush,
            #[cfg(test)]
            write_attempted: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn get(&self, key: &Key) -> Option<String> {
        if let Some(value) = self.pending.lock().ok()?.get(key) {
            return Some(value.value.clone());
        }
        let conn = self.conn.lock().ok()?;
        match key {
            Key::Selector(group, network) => conn.query_row(
                "SELECT member FROM selector WHERE grp = ?1 AND network = ?2",
                params![group, network],
                |row| row.get(0),
            ),
            Key::Clash(key) => conn.query_row(
                "SELECT value FROM clash_state WHERE key = ?1",
                [key],
                |row| row.get(0),
            ),
        }
        .ok()
    }

    fn set(&self, key: Key, value: String) {
        let sequence = self
            .next_sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Ok(mut pending) = self.pending.lock() else {
            tracing::warn!("state cache pending-write lock poisoned");
            return;
        };
        let previous = pending.insert(
            key.clone(),
            PendingWrite {
                sequence,
                value: value.clone(),
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
            tracing::warn!(%error, "state cache writer closed; point write rejected");
            return;
        }
        drop(pending);
        self.flush.notify();
    }

    fn flush_pending(&self) -> Result<(), CacheDbError> {
        flush_pending_writes(&self.pending, &self.writer)
    }

    fn request(
        &self,
        write: impl FnOnce(mpsc::Sender<Result<(), CacheDbError>>) -> Write,
    ) -> Result<(), CacheDbError> {
        let (ack, result) = mpsc::channel();
        self.writer
            .send(write(ack))
            .map_err(|_| CacheDbError::Closed)?;
        result.recv().map_err(|_| CacheDbError::Closed)?
    }

    pub fn load_network_selector(
        &self,
        group: &str,
        network: SelectionNetwork,
    ) -> Option<Result<SelectorMember, serde_json::Error>> {
        self.get(&Key::Selector(group.to_owned(), network_name(network)))
            .map(|value| serde_json::from_str(&value))
    }

    pub(crate) fn save_network_selector(
        &self,
        group: &str,
        network: SelectionNetwork,
        member: &SelectorMember,
    ) {
        self.set(
            Key::Selector(group.to_owned(), network_name(network)),
            serde_json::to_string(member).expect("selector identity serializes"),
        );
    }

    pub fn load_clash_mode(&self) -> Option<String> {
        self.get(&Key::Clash("mode"))
    }

    pub fn save_clash_mode(&self, mode: &str) {
        self.set(Key::Clash("mode"), mode.to_owned());
    }

    /// The Clash GLOBAL selection.
    pub fn load_clash_global(&self) -> Option<String> {
        self.get(&Key::Clash("global"))
    }

    pub fn save_clash_global(&self, selection: &str) {
        self.set(Key::Clash("global"), selection.to_owned());
    }

    /// Records `(node, delay_ms, measured_at_unix)` samples in one transaction
    /// (sing-box URLTest history storage parity: selections formed right after
    /// a restart must not start cold).
    pub fn save_delay_samples(&self, samples: Vec<(String, u64, u64)>) {
        if samples.is_empty() {
            return;
        }
        if let Err(error) = self.writer.send(Write::Delays(samples)) {
            tracing::warn!(%error, "state cache writer closed; delay batch rejected");
        }
    }

    /// Every delay sample no older than `max_age_secs` relative to `now_unix`,
    /// as `(node, delay_ms, measured_at_unix)`. Older or zero samples are
    /// deleted.
    pub fn load_delay_samples(&self, now_unix: u64, max_age_secs: u64) -> Vec<(String, u64, u64)> {
        let cutoff = now_unix.saturating_sub(max_age_secs);
        let rows = (|| -> rusqlite::Result<Vec<(String, u64, u64)>> {
            let conn = self
                .conn
                .lock()
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let mut statement = conn.prepare(
                "SELECT node, delay_ms, measured_at FROM delay_sample
                 WHERE measured_at >= ?1 AND measured_at > 0 AND delay_ms > 0",
            )?;
            statement
                .query_map([unix(cutoff)], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.unsigned_abs(),
                        row.get::<_, i64>(2)?.unsigned_abs(),
                    ))
                })?
                .collect()
        })();
        if let Err(error) = self.writer.send(Write::DeleteDelaysBefore(cutoff)) {
            tracing::warn!(%error, "state cache writer closed; delay prune rejected");
        }
        rows.unwrap_or_else(|error| {
            tracing::warn!(error = %CacheDbError::from(error), "state cache delay load failed");
            Vec::new()
        })
    }

    /// Writes DNS rows in one transaction; on failure the rows come back.
    pub(crate) fn write_dns(&self, entries: Vec<DnsRow>) -> Result<DnsWrite, DnsWriteError> {
        if entries.is_empty() {
            return Ok(DnsWrite::Written);
        }
        #[cfg(test)]
        self.write_attempted
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (ack, result) = mpsc::channel();
        if let Err(mpsc::SendError(write)) = self.writer.send(Write::Dns(entries, ack)) {
            let Write::Dns(entries, _) = write else {
                unreachable!("the rejected write is the one sent")
            };
            return Err((CacheDbError::Closed, entries));
        }
        result
            .recv()
            .unwrap_or_else(|_| Err((CacheDbError::Closed, Vec::new())))
    }

    /// Calls `visit(key, entry)` for every DNS row, one row at a time.
    pub(crate) fn for_each_dns(
        &self,
        mut visit: impl FnMut(&str, &[u8]),
    ) -> Result<(), CacheDbError> {
        let conn = self.conn.lock().map_err(|_| CacheDbError::Closed)?;
        let mut statement = conn.prepare("SELECT key, entry FROM dns_answer")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let key = row.get_ref(0)?.as_str().map_err(rusqlite::Error::from)?;
            visit(
                key,
                row.get_ref(1)?.as_blob().map_err(rusqlite::Error::from)?,
            );
        }
        Ok(())
    }

    /// Every DNS row as `(key, entry)`.
    #[cfg(test)]
    pub(crate) fn load_dns(&self) -> Result<Vec<(String, Vec<u8>)>, CacheDbError> {
        let mut rows = Vec::new();
        self.for_each_dns(|key, entry| rows.push((key.to_owned(), entry.to_vec())))?;
        Ok(rows)
    }

    /// Groups with a stored Selector choice.
    pub(crate) fn selector_groups(&self) -> Result<Vec<String>, CacheDbError> {
        self.keys("SELECT DISTINCT grp FROM selector")
    }

    /// Nodes with a stored delay sample.
    pub(crate) fn delay_nodes(&self) -> Result<Vec<String>, CacheDbError> {
        self.keys("SELECT node FROM delay_sample")
    }

    fn keys(&self, sql: &str) -> Result<Vec<String>, CacheDbError> {
        let conn = self.conn.lock().map_err(|_| CacheDbError::Closed)?;
        let mut statement = conn.prepare(sql)?;
        let keys = statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(keys)
    }

    pub(crate) fn maintain(&self, work: Maintenance) -> Result<(), CacheDbError> {
        self.flush_pending()?;
        self.request(|ack| Write::Maintain(work, ack))
    }

    pub(crate) fn flush_dns(&self) -> Result<(), CacheDbError> {
        self.request(Write::FlushDns)
    }

    #[cfg(any(feature = "native-api", test))]
    pub(crate) fn delete_dns_entries(&self, keys: &[String]) -> Result<(), CacheDbError> {
        self.request(|ack| Write::DeleteDns(keys.to_vec(), ack))
    }

    /// A cache over a new state db in `directory`.
    #[cfg(test)]
    pub(crate) fn in_dir(directory: &std::path::Path) -> Self {
        Self::open(Arc::new(StateDb::open(directory).expect("state db"))).expect("state cache")
    }

    #[cfg(test)]
    pub(crate) fn set_query_only_for_test(&self, enabled: bool) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.pragma_update(None, "query_only", enabled);
        }
        let _ = self.request(|ack| Write::SetQueryOnly(enabled, ack));
    }

    #[cfg(test)]
    pub(crate) fn lock_for_test(&self) -> CacheDbWriterGuard {
        let (entered, ready) = mpsc::channel();
        let (release, released) = mpsc::channel();
        self.writer
            .send(Write::Block(entered, released))
            .expect("state cache writer available");
        ready.recv().expect("state cache writer blocked");
        CacheDbWriterGuard { release }
    }

    #[cfg(test)]
    pub(crate) fn write_attempted_for_test(&self) -> bool {
        self.write_attempted
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Delay samples older than this are pruned.
pub(crate) const DELAY_SAMPLE_MAX_AGE_SECS: u64 = 24 * 3600;

/// Names the config holds when a tick starts.
pub(crate) struct Live {
    selector_groups: HashSet<String>,
    nodes: HashSet<String>,
}

impl Live {
    pub(crate) fn of(config: &honk_config::Config) -> Self {
        Self {
            selector_groups: config
                .groups
                .iter()
                .filter(|group| group.policy == honk_config::group::GroupPolicy::Selector)
                .map(|group| group.name.clone())
                .collect(),
            nodes: config.nodes.iter().map(|node| node.name.clone()).collect(),
        }
    }
}

/// Keys that were missing from the config at the previous tick, one per row.
#[derive(Default)]
pub(crate) struct Missing {
    groups: HashSet<String>,
    nodes: HashSet<String>,
    bodies: HashSet<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TickOwners {
    pub(crate) store_dns: bool,
    pub(crate) store_subscribe: bool,
}

/// One maintenance tick. With `store_subscribe`, deletes subscription bodies
/// whose subscription was not enabled at this tick and the previous one. With
/// the cache open, writes `samples`, deletes Selector and delay rows whose
/// group or node was missing at this tick and the previous one, delay rows
/// older than 24 h and, with `store_dns`, expired DNS rows, then runs
/// `incremental_vacuum`. The two-tick rule keeps rows across a config that
/// briefly drops and restores a group, node or subscription.
pub(crate) fn maintenance_tick(
    state: &StateDb,
    db: Option<&CacheDb>,
    live: &Live,
    samples: Vec<(String, u64, u64)>,
    missing: &mut Missing,
    owners: TickOwners,
    now: u64,
) {
    if owners.store_subscribe
        && let Err(error) = crate::subscription::prune_bodies(state, &mut missing.bodies)
    {
        tracing::warn!(%error, "state db subscription body maintenance failed");
    }
    let Some(db) = db else {
        return;
    };
    db.save_delay_samples(samples);
    let stale = |rows: Result<Vec<String>, _>,
                 present: &HashSet<String>,
                 previous: &mut HashSet<String>| {
        let current: HashSet<String> = match rows {
            Ok(rows) => rows
                .into_iter()
                .filter(|key| !present.contains(key))
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "state db maintenance read failed");
                HashSet::new()
            }
        };
        let expired = current.intersection(previous).cloned().collect();
        *previous = current;
        expired
    };
    let work = Maintenance {
        groups: stale(
            db.selector_groups(),
            &live.selector_groups,
            &mut missing.groups,
        ),
        nodes: stale(db.delay_nodes(), &live.nodes, &mut missing.nodes),
        delay_cutoff: now.saturating_sub(DELAY_SAMPLE_MAX_AGE_SECS),
        dns_expired_at: owners.store_dns.then_some(now),
    };
    if let Err(error) = db.maintain(work) {
        tracing::warn!(%error, "state db maintenance failed");
    }
}

#[cfg(test)]
mod tests;
