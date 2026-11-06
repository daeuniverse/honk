//! Process-scoped client DNS history; retained wire is never a clipped RRset.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use parking_lot::{Mutex, MutexGuard};

use crate::dns::outcome::{DnsOutcome, RequestRoute};
use crate::dns::query::IngressProfile;
use crate::dns::response::presentation::{self, DnsQuestion};

pub(crate) const MAX_RECORDS: usize = 512;
const MAX_BYTES: usize = 8 * 1024 * 1024;

pub(crate) struct DnsHistory {
    instance: String,
    allowed: bool,
    recording: AtomicBool,
    epoch: AtomicU64,
    inner: Mutex<Ring>,
}

struct Ring {
    entries: VecDeque<Entry>,
    bytes: usize,
    sequence: u64,
    limit: usize,
}

pub(crate) struct Entry {
    pub(crate) sequence: u64,
    pub(crate) observed_at: SystemTime,
    pub(crate) source: Option<SocketAddr>,
    pub(crate) question: DnsQuestion,
    pub(crate) qtype: u16,
    pub(crate) query: Box<[u8]>,
    pub(crate) response: Box<[u8]>,
    pub(crate) ingress: IngressProfile,
    pub(crate) cached: bool,
    pub(crate) upstream: Option<Box<str>>,
    pub(crate) route: RequestRoute,
    pub(crate) elapsed_ms: u64,
    bytes: usize,
}

impl DnsHistory {
    pub(crate) fn new(instance: String, recording: bool) -> Self {
        Self {
            instance,
            allowed: recording,
            recording: AtomicBool::new(recording),
            epoch: AtomicU64::new(0),
            inner: Mutex::new(Ring {
                entries: VecDeque::new(),
                bytes: 0,
                sequence: 0,
                limit: MAX_RECORDS,
            }),
        }
    }

    pub(crate) fn instance(&self) -> &str {
        &self.instance
    }

    pub(crate) fn allowed(&self) -> bool {
        self.allowed
    }

    pub(crate) fn view(&self) -> impl Deref<Target = VecDeque<Entry>> + '_ {
        MutexGuard::map(self.inner.lock(), |ring| &mut ring.entries)
    }

    pub(crate) fn set_limit(&self, limit: usize) {
        let mut ring = self.inner.lock();
        ring.limit = limit;
        while ring.entries.len() > limit {
            ring.evict();
        }
    }

    pub(crate) fn set_recording(&self, recording: bool) {
        let mut ring = self.inner.lock();
        if self.recording.load(Ordering::Acquire) == recording {
            return;
        }
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.recording.store(recording, Ordering::Release);
        if !recording {
            ring.entries = VecDeque::new();
            ring.bytes = 0;
        }
    }

    pub(crate) fn recording(&self) -> bool {
        self.recording.load(Ordering::Acquire)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture(
        &self,
        query: &[u8],
        ingress: IngressProfile,
        source: Option<SocketAddr>,
        outcome: Option<&DnsOutcome>,
        response: &[u8],
        elapsed: Duration,
    ) {
        let epoch = self.epoch.load(Ordering::Acquire);
        if !self.recording.load(Ordering::Acquire)
            || matches!(ingress, IngressProfile::Api)
            || (matches!(ingress, IngressProfile::Internal) && source.is_none())
        {
            return;
        }
        let Ok(context) = presentation::context(query, ingress) else {
            return;
        };
        if presentation::measure(&context, response, usize::MAX).is_err() {
            return;
        }
        let Some(qtype) = context.qtype().map(|value| value.get()) else {
            return;
        };
        let cached = outcome.is_some_and(DnsOutcome::is_cached);
        let upstream = outcome
            .filter(|_| !cached)
            .and_then(DnsOutcome::final_upstream);
        let route = outcome.map(DnsOutcome::request_route);
        let metadata = upstream.map_or(0, str::len).saturating_add(
            route
                .and_then(|route| route.rule.as_deref())
                .map_or(0, str::len),
        );
        if query
            .len()
            .saturating_add(response.len())
            .saturating_add(metadata + 2048 + size_of::<Entry>())
            > MAX_BYTES
        {
            return;
        }
        let Ok(question) = presentation::question(query, ingress) else {
            return;
        };
        let bytes = query.len()
            + response.len()
            + metadata
            + question.name.capacity()
            + question.rtype.capacity()
            + question.class.capacity()
            + size_of::<Entry>()
            + 256;
        let mut ring = self.inner.lock();
        if !self.recording.load(Ordering::Acquire)
            || self.epoch.load(Ordering::Acquire) != epoch
            || ring.limit == 0
        {
            return;
        }
        let Some(sequence) = ring.sequence.checked_add(1) else {
            return;
        };
        while ring.entries.len() >= ring.limit || ring.bytes + bytes > MAX_BYTES {
            ring.evict();
        }
        ring.sequence = sequence;
        ring.bytes += bytes;
        ring.entries.push_back(Entry {
            sequence,
            observed_at: SystemTime::now(),
            source,
            question,
            qtype,
            query: query.into(),
            response: response.into(),
            ingress,
            cached,
            upstream: upstream.map(Into::into),
            route: route.cloned().unwrap_or_default(),
            elapsed_ms: elapsed
                .as_millis()
                .min(u128::from(crate::observe::MAX_SAFE_UINT)) as u64,
            bytes,
        });
    }
}

impl Ring {
    fn evict(&mut self) {
        if let Some(entry) = self.entries.pop_front() {
            self.bytes -= entry.bytes;
        }
    }
}
