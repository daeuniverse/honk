//! Process-local userspace evidence. Reads never consult routing or current groups.

use std::{
    collections::VecDeque,
    mem::size_of,
    net::SocketAddr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use parking_lot::Mutex;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{Events, MAX_SAFE_UINT, timestamp};

pub(crate) mod dns;
pub(crate) mod kernel;
pub(crate) mod producer;
pub(crate) mod record;
use honk_outbound::runtime::flow_observation::{GapReason, TransportStatus};
use record::{Input, InputValues, SnapshotRow, Step, StepData, Summary};

use super::vocab::{ConnectionState, DomainSource, Network, Plane, RuleSource};

pub(crate) const MAX_RECORDS: usize = 1024;
pub(crate) const MAX_STEPS: usize = 64;
pub(crate) const MAX_RULE_VALUES: usize = 256;
const MAX_BYTES: usize = 8 * 1024 * 1024;
/// Listings keep this much of the budget for their snapshots, so a ring that
/// has grown to its own limit still leaves room to page through it.
const SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
const MAX_SNAPSHOTS: usize = 8;
pub(crate) const TERMINAL_TTL: Duration = Duration::from_secs(300);
pub(crate) const SNAPSHOT_TTL: Duration = Duration::from_secs(30);
/// Records leave the ring one at a time as flows end, newer ones need the room
/// or a revision runs out, so a `flow.gap` per departure would shadow every
/// flow under load. Departures are reported at most once per interval, with
/// the cumulative `dropped_records`; the count itself never skips.
const EVICTED_GAP_INTERVAL: Duration = Duration::from_secs(10);
const MAX_TEXT: usize = 512;
const MAX_STEP_BYTES: usize = 64 * 1024;
// Kernel dictionaries and snapshots share the recorder's fixed userspace budget.
const OWNER_BYTES: usize = 256 * 1024 + kernel::MAX_RETAINED_BYTES;

pub(crate) struct FlowStore {
    instance_id: String,
    events: Arc<dyn Events>,
    recording: AtomicBool,
    inner: Mutex<Store>,
}

struct Store {
    recording: bool,
    max_records: usize,
    retention: Duration,
    earliest_ended: Option<Instant>,
    records: VecDeque<Record>,
    snapshots: Vec<Snapshot>,
    tombstones: VecDeque<(String, Instant)>,
    record_bytes: usize,
    snapshot_bytes: usize,
    dropped: u64,
    evicted_gap_at: Option<Instant>,
}

struct Record {
    summary: Summary,
    input: Input,
    steps: Vec<Step>,
    started: Instant,
    ended: Option<Instant>,
    redacted: bool,
    overflow: bool,
    missing: u8,
    reply_observed: bool,
    selected_attempt: Option<String>,
    mode_recorded: bool,
    bytes: usize,
}

/// The `trace.missing` reasons kept as bits of `Record::missing`, in wire order.
#[derive(Clone, Copy)]
enum Missing {
    NotInstrumented = 1,
    StartedLate = 2,
}

impl Missing {
    const ALL: [Self; 2] = [Self::NotInstrumented, Self::StartedLate];

    const fn as_str(self) -> &'static str {
        match self {
            Self::NotInstrumented => "not_instrumented",
            Self::StartedLate => "started_late",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Filters {
    network: String,
    state: String,
    connection_id: Option<String>,
    full: bool,
    limit: usize,
}

struct Snapshot {
    token: String,
    filters: Filters,
    rows: Vec<SnapshotRow>,
    observed_at: String,
    dropped: String,
    created: Instant,
    bytes: usize,
}

pub(crate) struct FlowGuard {
    store: Weak<FlowStore>,
    id: String,
    replied: AtomicBool,
    sent: AtomicBool,
}

pub(crate) struct ConnectionEvidence {
    pub(crate) chain: Vec<String>,
    pub(crate) chain_source: &'static str,
    pub(crate) rule_id: Option<String>,
    pub(crate) rule_expression: Option<String>,
    pub(crate) rule_source: RuleSource,
    pub(crate) domain_source: Option<DomainSource>,
    pub(crate) started_at: String,
}

impl Store {
    fn new(recording: bool) -> Self {
        Self {
            recording,
            max_records: MAX_RECORDS,
            retention: TERMINAL_TTL,
            earliest_ended: None,
            records: VecDeque::new(),
            snapshots: Vec::new(),
            tombstones: VecDeque::new(),
            record_bytes: 0,
            snapshot_bytes: 0,
            dropped: 0,
            evicted_gap_at: None,
        }
    }

    fn retained_record_bytes(&self) -> usize {
        self.record_bytes + (self.records.capacity() - self.records.len()) * size_of::<Record>()
    }

    /// Everything the owner holds; the records' own share is bounded in
    /// `enforce_limit`, the listings' in `page`.
    #[cfg(test)]
    fn bytes(&self) -> usize {
        OWNER_BYTES + self.retained_record_bytes() + self.snapshot_bytes
    }
}

impl FlowStore {
    pub(crate) fn new(instance_id: String, events: Arc<dyn Events>) -> Self {
        Self {
            instance_id,
            events,
            recording: AtomicBool::new(true),
            inner: Mutex::new(Store::new(true)),
        }
    }

    pub(crate) fn set_recording(&self, enabled: bool) {
        let mut store = self.inner.lock();
        if store.recording == enabled {
            return;
        }
        let max_records = store.max_records;
        let retention = store.retention;
        *store = Store::new(enabled);
        store.max_records = max_records;
        store.retention = retention;
        self.recording.store(enabled, Ordering::Release);
        self.gap(&store, "recording_changed");
    }

    pub(crate) fn set_limits(&self, max_records: usize, retention_seconds: u64) {
        let mut store = self.inner.lock();
        if max_records < store.max_records
            || Duration::from_secs(retention_seconds) < store.retention
        {
            store.snapshots.clear();
            store.snapshot_bytes = 0;
        }
        store.max_records = max_records;
        store.retention = Duration::from_secs(retention_seconds);
        let now = Instant::now();
        self.prune(&mut store, now);
        self.enforce_limit(&mut store, now);
        store.records.shrink_to_fit();
        store.snapshots.shrink_to_fit();
    }

    pub(crate) fn maintain(&self) {
        if !self.recording.load(Ordering::Acquire) {
            return;
        }
        self.prune(&mut self.inner.lock(), Instant::now());
    }

    pub(crate) fn begin(
        self: &Arc<Self>,
        network: Network,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Option<FlowGuard> {
        if !self.recording.load(Ordering::Acquire) {
            return None;
        }
        let mut store = self.inner.lock();
        if !store.recording {
            return None;
        }
        let now = Instant::now();
        let id = Uuid::new_v4().to_string();
        let mut record = Record {
            summary: Summary {
                id: id.clone(),
                instance_id: self.instance_id.clone(),
                revision: 1,
                network,
                state: ConnectionState::Observed,
                pname: None,
                connection_id: None,
                outbound: None,
                chain: Vec::new(),
                chain_source: "unknown",
                rule_id: None,
                rule_generation_id: None,
                rule_expression: None,
                rule_source: RuleSource::Unknown,
                ingress: (),
                domain_source: None,
                observed_by: "userspace",
                started_at: timestamp(SystemTime::now()),
                ended_at: None,
                trace_status: "complete",
            },
            input: Input {
                src,
                dst,
                domain: None,
                domain_source: None,
                pid: None,
                process_path: (),
                src_mac: None,
                ingress: (),
                domain_rule_ids: (),
                dscp: None,
                mark: None,
            },
            steps: Vec::new(),
            started: now,
            ended: None,
            redacted: false,
            overflow: false,
            missing: 0,
            reply_observed: false,
            selected_attempt: None,
            mode_recorded: false,
            bytes: 0,
        };
        record.push_step(
            None,
            StepData::Input {
                values: InputValues {
                    input: record.input.clone(),
                    pname: None,
                },
                source: "socket",
            },
        );
        record.bytes = record.retained_bytes();
        store.record_bytes += record.bytes;
        self.updated(&record);
        store.records.push_back(record);
        self.enforce_limit(&mut store, now);
        Some(FlowGuard {
            store: Arc::downgrade(self),
            id,
            replied: AtomicBool::new(false),
            sent: AtomicBool::new(false),
        })
    }

    pub(crate) fn connection_evidence(&self, flow_id: &str) -> Option<ConnectionEvidence> {
        let mut store = self.inner.lock();
        self.prune(&mut store, Instant::now());
        let record = store.records.iter().find(|record| record.id() == flow_id)?;
        let summary = &record.summary;
        Some(ConnectionEvidence {
            chain: summary.chain.clone(),
            chain_source: summary.chain_source,
            rule_id: summary.rule_id.clone(),
            rule_expression: summary.rule_expression.clone(),
            rule_source: summary.rule_source,
            domain_source: summary.domain_source,
            started_at: summary.started_at.clone(),
        })
    }

    /// Expiry stays with the sampler tick; the connection path only pays for
    /// its own record, which is usually near the back of the ring.
    fn mutate(&self, id: &str, change: impl FnOnce(&mut Record) -> bool) -> bool {
        let mut store = self.inner.lock();
        let now = Instant::now();
        let Some(index) = store.records.iter().rposition(|record| record.id() == id) else {
            return false;
        };
        let record = &mut store.records[index];
        if record.ended.is_some() {
            return false;
        }
        let old_bytes = record.bytes;
        if !change(record) {
            return false;
        }
        let revision = record.summary.revision;
        if revision == MAX_SAFE_UINT {
            self.evict(&mut store, index, now, "buffer_overflow");
            return false;
        }
        record.summary.trace_status = record.trace_status();
        record.summary.revision += 1;
        record.bytes = record.retained_bytes();
        let new_bytes = record.bytes;
        let ended = record.ended;
        self.updated(record);
        store.record_bytes = store.record_bytes - old_bytes + new_bytes;
        if let Some(ended) = ended {
            store.earliest_ended = Some(
                store
                    .earliest_ended
                    .map_or(ended, |earliest| earliest.min(ended)),
            );
        }
        if self.enforce_limit(&mut store, now) {
            store.records.iter().any(|record| record.id() == id)
        } else {
            true
        }
    }

    pub(crate) fn record_step(&self, id: &str, generation: Option<u64>, data: StepData) -> bool {
        self.record_with(id, generation, |_| Some(data))
    }

    fn record_with(
        &self,
        id: &str,
        generation: Option<u64>,
        build: impl FnOnce(&Record) -> Option<StepData>,
    ) -> bool {
        let mut accepted = false;
        let retained = self.mutate(id, |record| {
            if record.steps.len() == MAX_STEPS {
                return record.mark_gap(GapReason::BufferOverflow);
            }
            let Some(mut data) = build(record) else {
                return false;
            };
            let mut redacted = false;
            let mut overflow = false;
            if !data.sanitize(&mut redacted, &mut overflow) {
                return record.mark_gap(if overflow {
                    GapReason::BufferOverflow
                } else {
                    GapReason::Redacted
                });
            }
            if size_of::<StepData>() + data.heap_bytes() > MAX_STEP_BYTES {
                return record.mark_gap(GapReason::BufferOverflow);
            }
            let changed = (redacted && !record.redacted) || (overflow && !record.overflow);
            record.redacted |= redacted;
            record.overflow |= overflow;
            let previous_count = record.steps.len();
            let pushed = record.push_step(
                generation.map(|generation| format!("{}:{generation}", self.instance_id)),
                data,
            );
            accepted = record.steps.len() != previous_count;
            pushed || changed
        });
        accepted && retained
    }

    pub(crate) fn mark_gap(&self, id: &str, reason: GapReason) {
        self.mutate(id, |record| record.mark_gap(reason));
    }

    fn updated(&self, record: &Record) {
        self.events
            .flow_updated(record.id(), record.summary.revision);
    }

    /// Gaps are unscoped: they report lost continuity or records the store no
    /// longer holds. A record that truncated its own steps shows that through
    /// its `overflow` flag and `flow.updated` instead.
    fn gap(&self, store: &Store, reason: &'static str) {
        self.events.publish(
            "flow.gap",
            json!({
                "resource_id": null, "reason": reason, "dropped_records": store.dropped.to_string()
            }),
            None,
        );
    }

    fn evict(&self, store: &mut Store, index: usize, now: Instant, reason: &'static str) {
        let record = store.records.remove(index).expect("known record index");
        store.record_bytes -= record.bytes;
        store.dropped = store.dropped.saturating_add(1);
        if store
            .evicted_gap_at
            .is_none_or(|at| now.saturating_duration_since(at) >= EVICTED_GAP_INTERVAL)
        {
            store.evicted_gap_at = Some(now);
            self.gap(store, reason);
        }
        if store.tombstones.len() == MAX_RECORDS {
            store.tombstones.pop_front();
        }
        store.tombstones.push_back((record.id().to_owned(), now));
    }

    /// Expired records give way first, then ended ones, before a live one is
    /// evicted for room.
    /// Returns whether pruning or eviction may have changed record membership.
    fn enforce_limit(&self, store: &mut Store, now: Instant) -> bool {
        let over = |store: &Store| {
            store.records.len() > store.max_records
                || OWNER_BYTES + store.retained_record_bytes() > MAX_BYTES - SNAPSHOT_BYTES
        };
        if !over(store) {
            return false;
        }
        self.prune(store, now);
        while over(store) {
            if store.records.is_empty() {
                break;
            }
            let index = store
                .records
                .iter()
                .position(|record| record.ended.is_some())
                .unwrap_or(0);
            self.evict(store, index, now, "buffer_overflow");
        }
        true
    }

    fn prune(&self, store: &mut Store, now: Instant) {
        store
            .snapshots
            .retain(|snapshot| now.saturating_duration_since(snapshot.created) < SNAPSHOT_TTL);
        store.snapshot_bytes = store.snapshots.iter().map(|snapshot| snapshot.bytes).sum();
        while store
            .tombstones
            .front()
            .is_some_and(|(_, at)| now.saturating_duration_since(*at) >= TERMINAL_TTL)
        {
            store.tombstones.pop_front();
        }
        if store
            .earliest_ended
            .is_none_or(|ended| now.saturating_duration_since(ended) < store.retention)
        {
            return;
        }
        let mut earliest_ended: Option<Instant> = None;
        let mut index = 0;
        while index < store.records.len() {
            let Some(ended) = store.records[index].ended else {
                index += 1;
                continue;
            };
            if now.saturating_duration_since(ended) >= store.retention {
                self.evict(store, index, now, "evicted");
            } else {
                earliest_ended = Some(earliest_ended.map_or(ended, |earliest| earliest.min(ended)));
                index += 1;
            }
        }
        store.earliest_ended = earliest_ended;
    }

    pub(crate) fn page(
        &self,
        filters: Filters,
        cursor: Option<&str>,
    ) -> Result<Value, PageRefusal> {
        let mut store = self.inner.lock();
        self.prune(&mut store, Instant::now());
        if let Some(cursor) = cursor {
            let (token, offset) = cursor.rsplit_once('.').ok_or(PageRefusal::Expired)?;
            let offset = offset.parse::<usize>().map_err(|_| PageRefusal::Expired)?;
            let snapshot = store
                .snapshots
                .iter()
                .find(|snapshot| snapshot.token == token)
                .ok_or(PageRefusal::Expired)?;
            if offset == 0 || offset >= snapshot.rows.len() || offset % snapshot.filters.limit != 0
            {
                return Err(PageRefusal::Expired);
            }
            if snapshot.filters != filters {
                return Err(PageRefusal::Mismatch);
            }
            return Ok(self.snapshot_page(snapshot, offset, store.recording));
        }
        let count = store
            .records
            .iter()
            .filter(|record| filters.matches(record))
            .count();
        // Only a walk that continues past this page keeps a snapshot; a result
        // that fits in one page is answered from the records and costs no budget.
        let retained = count > filters.limit;
        let mut snapshot = Snapshot {
            token: Uuid::new_v4().to_string(),
            filters,
            rows: Vec::with_capacity(count),
            observed_at: timestamp(SystemTime::now()),
            dropped: store.dropped.to_string(),
            created: Instant::now(),
            bytes: size_of::<Snapshot>() + count * size_of::<SnapshotRow>() + 8192,
        };
        for record in store
            .records
            .iter()
            .rev()
            .filter(|record| snapshot.filters.matches(record))
        {
            let row = SnapshotRow {
                summary: record.summary.clone(),
                input: snapshot.filters.full.then(|| record.input.clone()),
            };
            snapshot.bytes += row.heap_bytes();
            if retained && snapshot.bytes > SNAPSHOT_BYTES {
                return Err(PageRefusal::Busy);
            }
            snapshot.rows.push(row);
        }
        if retained {
            // Older snapshots make room before a new walk is refused: a reader
            // still on one of those cursors gets `snapshot_expired` and starts
            // over, which the ttl would have given it thirty seconds later.
            while !store.snapshots.is_empty()
                && (store.snapshots.len() == MAX_SNAPSHOTS
                    || store.snapshot_bytes + snapshot.bytes > SNAPSHOT_BYTES)
            {
                let oldest = store
                    .snapshots
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, snapshot)| snapshot.created)
                    .map(|(index, _)| index)
                    .expect("a non-empty snapshot table has an oldest entry");
                let stale = store.snapshots.remove(oldest);
                store.snapshot_bytes -= stale.bytes;
            }
        }
        let page = self.snapshot_page(&snapshot, 0, store.recording);
        if retained {
            store.snapshot_bytes += snapshot.bytes;
            store.snapshots.push(snapshot);
        }
        Ok(page)
    }

    fn snapshot_page(&self, snapshot: &Snapshot, offset: usize, recording: bool) -> Value {
        let end = (offset + snapshot.filters.limit).min(snapshot.rows.len());
        json!({
            "instance_id": self.instance_id, "observed_at": snapshot.observed_at,
            "coverage": coverage(recording), "dropped_records": snapshot.dropped,
            "flows": &snapshot.rows[offset..end],
            "next_cursor": (end < snapshot.rows.len()).then(|| format!("{}.{}", snapshot.token, end))
        })
    }

    pub(crate) fn get(&self, flow_id: &str) -> Result<Value, FlowMissing> {
        let mut store = self.inner.lock();
        self.prune(&mut store, Instant::now());
        if let Some(record) = store.records.iter().find(|record| record.id() == flow_id) {
            return Ok(record.project());
        }
        if store
            .tombstones
            .iter()
            .any(|(expired, _)| expired == flow_id)
        {
            Err(FlowMissing::Expired)
        } else {
            Err(FlowMissing::NotFound)
        }
    }

    #[cfg(test)]
    pub(crate) fn test_detail(&self, flow_id: &str) -> Value {
        self.get(flow_id).unwrap()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PageRefusal {
    /// The cursor is unknown, expired or past its snapshot.
    Expired,
    /// The cursor belongs to a walk under other filters or page size.
    Mismatch,
    Busy,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FlowMissing {
    Expired,
    NotFound,
}

impl Record {
    fn id(&self) -> &str {
        &self.summary.id
    }

    fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self.summary.heap_bytes()
            + self.selected_attempt.as_ref().map_or(0, String::capacity)
            + self.input.heap_bytes()
            + self.steps.capacity() * size_of::<Step>()
            + self.steps.iter().map(Step::heap_bytes).sum::<usize>()
    }

    /// The generation of the latest traffic-route step that carries `rule_id`.
    pub(super) fn rule_generation(&self, rule_id: Option<&str>) -> Option<String> {
        let rule_id = rule_id?;
        self.steps
            .iter()
            .rev()
            .find(|step| {
                matches!(&step.data, StepData::Route { chain: "traffic", rule_id: Some(id), .. } if id == rule_id)
            })
            .and_then(|step| step.generation_id.clone())
    }

    fn push_step(&mut self, generation_id: Option<String>, mut data: StepData) -> bool {
        if self.steps.len() == MAX_STEPS {
            return !std::mem::replace(&mut self.overflow, true);
        }
        if !self.references_known(&data) && self.missing == 0 && !self.overflow && !self.redacted {
            self.mark_gap(GapReason::NotInstrumented);
        }
        if missing_source_evidence(&data) {
            self.mark_gap(GapReason::NotInstrumented);
        }
        if let StepData::Connection { reply_received, .. } = &mut data {
            self.reply_observed |= *reply_received == Some(true);
            if reply_received.is_some() && self.reply_observed {
                *reply_received = Some(true);
            }
        }
        if let StepData::Route {
            chain: "traffic",
            plane,
            rule_id,
            rules,
            outbound,
            ..
        } = &data
        {
            self.summary.outbound = outbound.clone();
            self.summary.rule_id = rule_id.clone();
            self.summary.rule_generation_id = rule_id.as_ref().and(generation_id.clone());
            self.summary.rule_expression = rule_id.as_ref().and_then(|id| {
                rules
                    .iter()
                    .find(|rule| &rule.rule_id == id)
                    .filter(|rule| record::safe_expression(&rule.expression))
                    .map(|rule| rule.expression.clone())
            });
            self.summary.rule_source = match plane {
                Plane::Kernel => RuleSource::Kernel,
                Plane::Userspace => RuleSource::Recomputed,
            };
            self.mode_recorded = false;
        }
        let elapsed = self.started.elapsed().as_micros();
        self.steps.push(Step {
            seq: self.steps.len() + 1,
            observed_at: SystemTime::now(),
            elapsed_us: (elapsed <= u128::from(MAX_SAFE_UINT)).then_some(elapsed as u64),
            generation_id,
            evidence: "observed",
            data,
        });
        true
    }

    fn mark_gap(&mut self, reason: GapReason) -> bool {
        let flag = match reason {
            GapReason::BufferOverflow => return !std::mem::replace(&mut self.overflow, true),
            GapReason::Redacted => return !std::mem::replace(&mut self.redacted, true),
            GapReason::StartedLate => Missing::StartedLate,
            GapReason::NotInstrumented
            | GapReason::SharedDialContinuesAfterWaiter
            | GapReason::RetirementOwnerLost => Missing::NotInstrumented,
        } as u8;
        let changed = self.missing & flag == 0;
        self.missing |= flag;
        changed
    }

    fn trace_status(&self) -> &'static str {
        if self.missing != 0 || self.overflow || self.redacted {
            "partial"
        } else {
            "complete"
        }
    }

    fn references_known(&self, data: &StepData) -> bool {
        let route = |id: &str| {
            self.steps.iter().any(|step| {
            matches!(&step.data, StepData::Route { evaluation_id, .. } if evaluation_id == id)
        })
        };
        let attempt = |id: &str| {
            self.steps.iter().any(|step| {
            matches!(&step.data, StepData::Outbound { attempt_id, .. } if attempt_id == id)
        })
        };
        let lookup = |id: Uuid| {
            self.steps
                .iter()
                .any(|step| matches!(&step.data, StepData::Dns(data) if data.lookup_id == id))
        };
        match data {
            StepData::Reroute {
                from_evaluation_id,
                to_evaluation_id,
                ..
            } => {
                from_evaluation_id.as_deref().is_none_or(route)
                    && to_evaluation_id.as_deref().is_none_or(route)
            }
            StepData::Outbound { attempt: data, .. } => {
                data.evaluation_id.as_deref().is_none_or(route)
                    && data.parent_attempt_id.as_deref().is_none_or(attempt)
                    && data
                        .lookup_id
                        .as_ref()
                        .is_none_or(|id| Uuid::try_parse(id).is_ok_and(lookup))
            }
            StepData::Dns(data) => {
                data.parent_lookup_id.is_none_or(lookup)
                    && data.attempt_id.is_none_or(|id| {
                        let mut text = Uuid::encode_buffer();
                        attempt(id.hyphenated().encode_lower(&mut text))
                    })
                    && data.route_evaluation_ids.iter().all(|id| route(id))
            }
            StepData::Connection {
                attempt_id,
                lookup_id,
                ..
            } => {
                attempt_id.as_deref().is_none_or(attempt)
                    && lookup_id
                        .as_ref()
                        .is_none_or(|id| Uuid::try_parse(id).is_ok_and(lookup))
            }
            _ => true,
        }
    }

    fn has_open_operations(&self) -> bool {
        self.steps.iter().enumerate().any(|(index, step)| match &step.data {
            StepData::Outbound { attempt_id, status: TransportStatus::Started, .. } => {
                !self.steps[index + 1..].iter().any(|later| {
                    matches!(&later.data, StepData::Outbound { attempt_id: id, status, .. } if id == attempt_id && *status != TransportStatus::Started)
                })
            }
            StepData::Dns(data) if data.status == "started" => {
                !self.steps[index + 1..].iter().any(|later| {
                    matches!(&later.data, StepData::Dns(later) if later.lookup_id == data.lookup_id && !matches!(later.status, "started" | "joined"))
                })
            }
            _ => false,
        })
    }

    fn project(&self) -> Value {
        let mut row = json!(self.summary);
        row["input"] = json!(self.input);
        let mut missing: Vec<_> = Missing::ALL
            .into_iter()
            .filter(|flag| self.missing & *flag as u8 != 0)
            .map(Missing::as_str)
            .collect();
        if self.overflow {
            missing.push("buffer_overflow");
        }
        if self.redacted {
            missing.push("redacted");
        }
        row["trace"] =
            json!({"status": self.summary.trace_status, "missing": missing, "steps": self.steps});
        row
    }
}

fn missing_source_evidence(data: &StepData) -> bool {
    let incomplete_selection = |rows: &[record::Selection]| {
        rows.iter().any(|row| {
            matches!(
                row.policy,
                "urltest" | "url_test" | "load_balance" | "loadbalance" | "fallback" | "score"
            ) && row.selection.is_none()
        })
    };
    match data {
        StepData::Route {
            rules,
            input,
            chain,
            dns_action,
            ..
        } => {
            input.is_none()
                || rules.is_empty()
                || rules.iter().any(|rule| {
                    rule.result == "indeterminate"
                        || rule
                            .conditions
                            .iter()
                            .any(|condition| condition.result == "indeterminate")
                })
                || (matches!(*chain, "dns_request" | "dns_response") && dns_action.is_none())
        }
        StepData::Outbound { attempt, .. } => {
            attempt.routing_source == super::vocab::RoutingSource::Unknown
                || attempt.mode_override == "unknown"
                || incomplete_selection(&attempt.selection_path)
        }
        StepData::Connection { selections, .. } => incomplete_selection(selections),
        _ => false,
    }
}

impl Filters {
    pub(crate) fn new(
        network: String,
        state: String,
        connection_id: Option<String>,
        full: bool,
        limit: usize,
    ) -> Self {
        Self {
            network,
            state,
            connection_id,
            full,
            limit,
        }
    }

    fn matches(&self, record: &Record) -> bool {
        (self.network == "all" || record.summary.network.as_str() == self.network)
            && (self.state == "all" || record.summary.state.as_str() == self.state)
            && self
                .connection_id
                .as_ref()
                .is_none_or(|id| record.summary.connection_id.as_ref() == Some(id))
    }
}

fn coverage(recording: bool) -> Value {
    let userspace = if recording { "partial" } else { "none" };
    json!({"userspace_tcp": userspace, "userspace_udp": userspace, "kernel_direct": "none",
        "kernel_block": "none", "dns_intercept": userspace, "kernel_bypass": "none"})
}

fn display_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}

fn bounded_display(value: &str, redacted: &mut bool, overflow: &mut bool) -> Option<String> {
    if value.is_empty() || value.chars().any(char::is_control) {
        *redacted = true;
        return None;
    }
    let mut end = value.len().min(MAX_TEXT);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    *overflow |= end < value.len();
    Some(value[..end].to_owned())
}

fn safe_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | '@'))
}

fn safe_optional(value: Option<&str>, redacted: &mut bool) -> Option<String> {
    value.and_then(|value| {
        if safe_text(value) {
            Some(value.to_owned())
        } else {
            *redacted = true;
            None
        }
    })
}

#[cfg(test)]
mod tests;
