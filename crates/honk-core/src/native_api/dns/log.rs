//! Process-scoped client DNS history; retained wire is never a clipped RRset.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::records::{self, DnsAnswer, DnsQuestion, MAX_JSON_BYTES};
use crate::dns::outcome::{DnsOutcome, RequestRoute};
use crate::dns::query::IngressProfile;
use crate::dns::response::native;
use crate::native_api::{
    ApiError, ErrorCode, NativeState, error, invalid_query, parse_query, timestamp,
    types::RequestId,
};

pub(crate) const MAX_RECORDS: usize = 512;
pub(crate) const MAX_PAGE_SIZE: usize = 500;
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

struct Entry {
    sequence: u64,
    observed_at: SystemTime,
    source: Option<SocketAddr>,
    question: DnsQuestion,
    qtype: u16,
    query: Box<[u8]>,
    response: Box<[u8]>,
    ingress: IngressProfile,
    cached: bool,
    upstream: Option<Box<str>>,
    route: RequestRoute,
    elapsed_ms: u64,
    bytes: usize,
}

impl crate::observe::DnsLog for DnsHistory {
    fn recording(&self) -> bool {
        DnsHistory::recording(self)
    }

    fn capture(
        &self,
        query: &[u8],
        ingress: IngressProfile,
        source: Option<SocketAddr>,
        outcome: Option<&DnsOutcome>,
        response: &[u8],
        elapsed: Duration,
    ) {
        DnsHistory::capture(self, query, ingress, source, outcome, response, elapsed);
    }
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

    pub(crate) fn capability(&self) -> serde_json::Value {
        serde_json::json!({"available": self.allowed, "min_records": crate::native_api::settings::MIN_RECORDS, "max_records": MAX_RECORDS, "max_page_size": MAX_PAGE_SIZE})
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
        let Ok(context) = native::context(query, ingress) else {
            return;
        };
        if native::measure(&context, response, usize::MAX).is_err() {
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
        let Ok(question) = records::question(query, ingress) else {
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

    /// `{sequence}:{issued}:{bound}`: `issued` proves this process issued
    /// the cursor, `bound` ties it to the filter and `limit`.
    fn cursor(&self, sequence: u64, filter: &Filter, limit: usize) -> String {
        let issued = self.issued(sequence);
        let mut digest = Sha256::new();
        digest.update(issued.as_bytes());
        digest.update(limit.to_be_bytes());
        let name = filter.name.as_deref().unwrap_or_default();
        digest.update(name.len().to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(
            filter
                .qtype
                .map(u32::from)
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        if let Some(source) = filter.source {
            match source {
                IpAddr::V4(value) => digest.update(value.octets()),
                IpAddr::V6(value) => digest.update(value.octets()),
            }
        }
        format!(
            "{sequence}:{issued}:{}",
            crate::configuration::encode_digest(&digest.finalize())
        )
    }

    fn issued(&self, sequence: u64) -> String {
        let digest = Sha256::new()
            .chain_update(self.instance.as_bytes())
            .chain_update(sequence.to_be_bytes())
            .finalize();
        crate::configuration::encode_digest(&digest)
    }

    fn page(
        &self,
        filter: Filter,
        limit: usize,
        cursor: Option<&str>,
        id: &RequestId,
    ) -> Result<Response, ApiError> {
        // ponytail: at most 512 records under one lock; indexed snapshots only if this ceiling grows.
        let ring = self.inner.lock();
        let anchor = if let Some(cursor) = cursor {
            let expired = || super::super::catalog::snapshot_expired(id);
            let mut parts = cursor.split(':');
            let sequence = parts
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(expired)?;
            if parts.next() != Some(self.issued(sequence).as_str())
                || !ring.entries.iter().any(|entry| entry.sequence == sequence)
            {
                return Err(expired());
            }
            if self.cursor(sequence, &filter, limit) != cursor {
                return Err(invalid_query(id));
            }
            sequence
        } else {
            u64::MAX
        };
        let mut selected = ring
            .entries
            .iter()
            .rev()
            .filter(|entry| entry.sequence < anchor && filter.matches(entry));
        let mut budget = MAX_JSON_BYTES - 512;
        let mut rows = Vec::new();
        let mut last = None;
        let mut full = false;
        for entry in selected.by_ref().take(limit) {
            let meta = Metadata {
                id: format!("{}:dns:{}", self.instance, entry.sequence),
                observed_at: timestamp(entry.observed_at),
                src: entry.source,
                question: &entry.question,
                status: records::status(&entry.response),
                cached: entry.cached,
                upstream: entry.upstream.as_deref(),
                route: &entry.route,
                elapsed_ms: entry.elapsed_ms,
            };
            let charge = records::json_size(&meta)
                .map_err(|_| unavailable(id))?
                .saturating_add(size_of::<Row<'_>>() + 16);
            let first = rows.is_empty();
            match budget.checked_sub(charge) {
                Some(rest) => budget = rest,
                None if first => budget = 0,
                None => {
                    full = true;
                    break;
                }
            }
            let Some(answers) = records::page_row(
                &entry.query,
                &entry.response,
                entry.ingress,
                &mut budget,
                first,
            )
            .map_err(|_| unavailable(id))?
            else {
                full = true;
                break;
            };
            rows.push(Row { meta, answers });
            last = Some(entry.sequence);
        }
        let more = full || selected.next().is_some();
        let page = Page {
            observed_at: timestamp(SystemTime::now()),
            total: ring.entries.len(),
            next_cursor: last
                .filter(|_| more)
                .map(|sequence| self.cursor(sequence, &filter, limit)),
            records: rows,
        };
        let bytes = records::json_size(&page).map_err(|_| unavailable(id))?;
        // A single record is served whole; see `records::page_row`.
        if bytes > MAX_JSON_BYTES && page.records.len() > 1 {
            return Err(unavailable(id));
        }
        let mut body = Vec::with_capacity(bytes);
        serde_json::to_writer(&mut body, &page).map_err(|_| unavailable(id))?;
        Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
    }
}

impl Ring {
    fn evict(&mut self) {
        if let Some(entry) = self.entries.pop_front() {
            self.bytes -= entry.bytes;
        }
    }
}

#[derive(Default)]
struct Filter {
    name: Option<String>,
    qtype: Option<u16>,
    source: Option<IpAddr>,
}

impl Filter {
    fn matches(&self, entry: &Entry) -> bool {
        self.qtype.is_none_or(|qtype| qtype == entry.qtype)
            && self.source.is_none_or(|source| {
                entry
                    .source
                    .is_some_and(|actual| actual.ip().to_canonical() == source)
            })
            && self.name.as_deref().is_none_or(|name| {
                entry
                    .question
                    .name
                    .as_bytes()
                    .windows(name.len())
                    .any(|part| part.eq_ignore_ascii_case(name.as_bytes()))
            })
    }
}

#[derive(Serialize)]
struct Metadata<'a> {
    id: String,
    observed_at: String,
    src: Option<SocketAddr>,
    question: &'a DnsQuestion,
    status: String,
    cached: bool,
    upstream: Option<&'a str>,
    route: &'a RequestRoute,
    elapsed_ms: u64,
}

#[derive(Serialize)]
struct Row<'a> {
    #[serde(flatten)]
    meta: Metadata<'a>,
    answers: Vec<DnsAnswer>,
}

#[derive(Serialize)]
struct Page<'a> {
    observed_at: String,
    total: usize,
    next_cursor: Option<String>,
    records: Vec<Row<'a>>,
}

fn unavailable(id: &RequestId) -> ApiError {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "DNS log response exceeds the projection budget",
        id,
    )
    .with_retry_after(1)
}

pub(super) async fn serve(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    if !state.observation.dns.log.allowed {
        return Err(error(
            StatusCode::NOT_FOUND,
            ErrorCode::CapabilityNotSupported,
            "DNS recording is disabled",
            id,
        ));
    }
    let query = parse_query(uri, &["name", "type", "src", "limit", "cursor"], id)?;
    if query.values().any(String::is_empty) {
        return Err(invalid_query(id));
    }
    let limit = query
        .get("limit")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| invalid_query(id))?
        .unwrap_or(100);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(invalid_query(id));
    }
    let qtype = query
        .get("type")
        .map(|value| records::parse_type(value).ok_or_else(|| invalid_query(id)))
        .transpose()?;
    let source = query
        .get("src")
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map(|ip| ip.to_canonical())
                .map_err(|_| invalid_query(id))
        })
        .transpose()?;
    let filter = Filter {
        name: query.get("name").map(|value| value.to_ascii_lowercase()),
        qtype,
        source,
    };
    state
        .observation
        .dns
        .log
        .page(filter, limit, query.get("cursor").map(String::as_str), id)
}

#[cfg(test)]
impl DnsHistory {
    pub(crate) fn page_for_test(&self) -> Response {
        self.page(
            Filter::default(),
            MAX_PAGE_SIZE,
            None,
            &RequestId("dns-log-test".into()),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(store: &DnsHistory, name: &str, source: Option<SocketAddr>) {
        let query = crate::dns::forwarder::build_dns_query(name, 1);
        let response = crate::dns::response::build_dns_refused(&query);
        store.capture(
            &query,
            IngressProfile::Udp {
                advertised_size: 512,
            },
            source,
            None,
            &response,
            Duration::from_millis(7),
        );
    }

    async fn value(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn ipv6_socket_filter_and_cursor_are_bound_to_retained_records() {
        let store = DnsHistory::new("first-instance".into(), true);
        let source: SocketAddr = "[2001:db8::12]:53210".parse().unwrap();
        capture(&store, "older.example", Some(source));
        capture(&store, "newer.example", Some(source));
        capture(
            &store,
            "excluded.example",
            Some("192.0.2.1:53".parse().unwrap()),
        );
        let id = RequestId("test".into());
        let filter = || Filter {
            source: Some(source.ip()),
            ..Default::default()
        };
        let first = value(store.page(filter(), 1, None, &id).unwrap()).await;
        assert_eq!(first["total"], 3);
        assert_eq!(first["records"][0]["src"], "[2001:db8::12]:53210");
        assert_eq!(first["records"][0]["question"]["name"], "newer.example.");
        let cursor = first["next_cursor"].as_str().unwrap();
        let second = value(store.page(filter(), 1, Some(cursor), &id).unwrap()).await;
        assert_eq!(second["records"][0]["question"]["name"], "older.example.");
        let status =
            |result: Result<Response, ApiError>| result.unwrap_err().into_response().status();
        assert_eq!(
            status(store.page(Filter::default(), 1, Some(cursor), &id)),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(store.page(filter(), 2, Some(cursor), &id)),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(store.page(filter(), 1, Some("1:forged:forged"), &id)),
            StatusCode::GONE
        );
        let other = DnsHistory::new("second-instance".into(), true);
        capture(&other, "older.example", Some(source));
        capture(&other, "newer.example", Some(source));
        assert_eq!(
            status(other.page(filter(), 1, Some(cursor), &id)),
            StatusCode::GONE
        );
        store.set_limit(1);
        assert_eq!(
            status(store.page(filter(), 1, Some(cursor), &id)),
            StatusCode::GONE
        );
        assert_eq!(value(store.page_for_test()).await["total"], 1);
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_diagnostic_and_background_calls_do_not_enter_history() {
        let owner =
            crate::native_api::observation::NativeObservation::new(&honk_config::Config::default());
        let store = owner.dns.log_for_test();
        capture(store, "disabled.example", None);
        owner
            .settings
            .renew(&owner, crate::native_api::settings::Demand::NONE);
        capture(store, "ordinary-events.example", None);
        owner
            .settings
            .renew(&owner, crate::native_api::settings::Demand::FLOWS);
        owner
            .settings
            .renew(&owner, crate::native_api::settings::Demand::LOGS);
        capture(store, "other-diagnostics.example", None);
        assert_eq!(value(store.page_for_test()).await["total"], 0);
        owner
            .settings
            .renew(&owner, crate::native_api::settings::Demand::DNS_LOG);
        let query = crate::dns::forwarder::build_dns_query("diagnostic.example", 1);
        let response = crate::dns::response::build_dns_refused(&query);
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:53000".parse().unwrap();
        store.capture(
            &query,
            IngressProfile::Api,
            Some(mapped),
            None,
            &response,
            Duration::ZERO,
        );
        store.capture(
            &query,
            IngressProfile::Internal,
            None,
            None,
            &response,
            Duration::ZERO,
        );
        assert_eq!(value(store.page_for_test()).await["total"], 0);
        store.capture(
            &query,
            IngressProfile::Internal,
            Some(mapped),
            None,
            &response,
            Duration::ZERO,
        );
        let filter = Filter {
            source: Some("192.0.2.1".parse().unwrap()),
            ..Default::default()
        };
        let page = value(
            store
                .page(filter, 1, None, &RequestId("test".into()))
                .unwrap(),
        )
        .await;
        assert_eq!(page["total"], 1);
        assert_eq!(page["records"][0]["src"], mapped.to_string());
        assert_eq!(page["records"][0]["status"], "REFUSED");
        tokio::time::advance(Duration::from_secs(59)).await;
        owner
            .settings
            .renew(&owner, crate::native_api::settings::Demand::FLOWS);
        owner
            .settings
            .renew(&owner, crate::native_api::settings::Demand::LOGS);
        tokio::time::advance(Duration::from_secs(1)).await;
        owner.settings.maintain(&owner);
        assert!(!store.recording());
        capture(store, "expired.example", None);
        assert_eq!(value(store.page_for_test()).await["total"], 0);
        owner
            .settings
            .renew(&owner, crate::native_api::settings::Demand::DNS_LOG);
        assert!(store.recording());
        assert_eq!(value(store.page_for_test()).await["total"], 0);
        capture(store, "renewed.example", None);
        let renewed = value(store.page_for_test()).await;
        assert_eq!(
            renewed["records"][0]["question"]["name"],
            "renewed.example."
        );
        assert_eq!(renewed["records"][0]["status"], "REFUSED");
    }

    #[tokio::test]
    async fn byte_eviction_retains_whole_unknown_records_and_never_clips_projection() {
        let store = DnsHistory::new("instance".into(), true);
        let query = crate::dns::forwarder::build_dns_query("large.example", 65000);
        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 12, 0xfd, 0xe8, 0, 1, 0, 0, 0, 1]);
        response.extend_from_slice(&60000u16.to_be_bytes());
        response.resize(response.len() + 60000, 0xab);
        for _ in 0..150 {
            store.capture(
                &query,
                IngressProfile::Tcp,
                None,
                None,
                &response,
                Duration::ZERO,
            );
        }
        let id = RequestId("test".into());
        let page = value(store.page(Filter::default(), 1, None, &id).unwrap()).await;
        let count = page["total"].as_u64().unwrap();
        assert!(count > 0 && count < 150);
        assert_eq!(
            page["records"][0]["answers"][0]["data"],
            format!("\\# 60000 {}", "AB".repeat(60000))
        );
    }

    #[tokio::test]
    async fn pages_end_early_at_the_projection_budget_and_walk_every_record_once() {
        let store = DnsHistory::new("instance".into(), true);
        let query = crate::dns::forwarder::build_dns_query("large.example", 65000);
        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 12, 0xfd, 0xe8, 0, 1, 0, 0, 0, 1]);
        response.extend_from_slice(&60000u16.to_be_bytes());
        response.resize(response.len() + 60000, 0xab);
        for _ in 0..7 {
            store.capture(
                &query,
                IngressProfile::Tcp,
                None,
                None,
                &response,
                Duration::ZERO,
            );
        }
        let id = RequestId("test".into());
        let data = format!("\\# 60000 {}", "AB".repeat(60000));
        let mut ids = std::collections::BTreeSet::new();
        let mut pages = 0;
        let mut cursor = None;
        loop {
            let page = value(
                store
                    .page(Filter::default(), MAX_PAGE_SIZE, cursor.as_deref(), &id)
                    .unwrap(),
            )
            .await;
            assert_eq!(page["total"], 7);
            let records = page["records"].as_array().unwrap();
            assert!(!records.is_empty());
            for record in records {
                assert_eq!(record["answers"][0]["data"], data);
                assert!(ids.insert(record["id"].as_str().unwrap().to_owned()));
            }
            pages += 1;
            match page["next_cursor"].as_str() {
                Some(next) => cursor = Some(next.to_owned()),
                None => break,
            }
        }
        assert_eq!(ids.len(), 7);
        assert!(pages > 1);
    }

    #[tokio::test]
    async fn a_record_larger_than_any_page_is_served_alone_and_the_walk_continues() {
        let store = DnsHistory::new("instance".into(), true);
        let domain = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        let query = crate::dns::forwarder::build_dns_query(&domain, 5);
        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&2000u16.to_be_bytes());
        for _ in 0..2000 {
            response.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
        }
        capture(&store, "older.example", None);
        store.capture(
            &query,
            IngressProfile::Tcp,
            None,
            None,
            &response,
            Duration::ZERO,
        );
        capture(&store, "newer.example", None);
        let id = RequestId("test".into());
        let mut pages = Vec::new();
        let mut cursor = None;
        loop {
            let page = value(
                store
                    .page(Filter::default(), 2, cursor.as_deref(), &id)
                    .unwrap(),
            )
            .await;
            let records = page["records"].as_array().unwrap();
            pages.push(
                records
                    .iter()
                    .map(|record| record["answers"].as_array().unwrap().len())
                    .collect::<Vec<_>>(),
            );
            match page["next_cursor"].as_str() {
                Some(next) => cursor = Some(next.to_owned()),
                None => break,
            }
        }
        assert_eq!(pages, [vec![0], vec![2000], vec![0]]);
    }
}
