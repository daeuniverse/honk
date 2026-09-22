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
use crate::dns::outcome::{DnsOutcome, Provenance, RequestRoute};
use crate::dns::query::IngressProfile;
use crate::dns::response::native;
use crate::native_api::{
    ApiError, ErrorCode, NativeState, error, invalid_query, parse_query, timestamp,
    types::RequestId,
};

pub(crate) const MAX_RECORDS: usize = 512;
pub(crate) const MAX_PAGE_SIZE: usize = 500;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_SAFE_UINT: u128 = 9_007_199_254_740_991;

pub(crate) struct LogStore {
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

impl LogStore {
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
        serde_json::json!({"available": self.allowed, "max_records": MAX_RECORDS, "max_page_size": MAX_PAGE_SIZE})
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
        let cached = outcome.is_some_and(|outcome| {
            matches!(outcome.provenance(), Provenance::Cache | Provenance::Stale)
        });
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
            elapsed_ms: elapsed.as_millis().min(MAX_SAFE_UINT) as u64,
            bytes,
        });
    }

    fn cursor(&self, sequence: u64, filter: &Filter) -> String {
        let mut digest = Sha256::new();
        digest.update(self.instance.as_bytes());
        digest.update(sequence.to_be_bytes());
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
            "{sequence}:{}",
            crate::configuration::encode_digest(&digest.finalize())
        )
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
            let sequence = cursor
                .split_once(':')
                .and_then(|(value, _)| value.parse::<u64>().ok())
                .ok_or_else(|| invalid_query(id))?;
            if self.cursor(sequence, &filter) != cursor
                || !ring.entries.iter().any(|entry| entry.sequence == sequence)
            {
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
            budget = budget.checked_sub(charge).ok_or_else(|| unavailable(id))?;
            let answers =
                records::project(&entry.query, &entry.response, entry.ingress, &mut budget)
                    .map_err(|_| unavailable(id))?;
            rows.push(Row { meta, answers });
            last = Some(entry.sequence);
        }
        let more = selected.next().is_some();
        let page = Page {
            observed_at: timestamp(SystemTime::now()),
            total: ring.entries.len(),
            next_cursor: last
                .filter(|_| more)
                .map(|sequence| self.cursor(sequence, &filter)),
            records: rows,
        };
        let bytes = records::json_size(&page).map_err(|_| unavailable(id))?;
        if bytes > MAX_JSON_BYTES {
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
                    .is_some_and(|actual| normalized_ip(actual.ip()) == source)
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

fn normalized_ip(value: IpAddr) -> IpAddr {
    match value {
        IpAddr::V6(value) => value.to_ipv4_mapped().map_or(IpAddr::V6(value), IpAddr::V4),
        value => value,
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
                .map(normalized_ip)
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
impl LogStore {
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

    fn capture(store: &LogStore, name: &str, source: Option<SocketAddr>) {
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
        let bytes = axum::body::to_bytes(response.into_body(), MAX_JSON_BYTES)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn ipv6_socket_filter_and_cursor_are_bound_to_retained_records() {
        let store = LogStore::new("first-instance".into(), true);
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
        assert!(store.page(Filter::default(), 1, Some(cursor), &id).is_err());
        let other = LogStore::new("second-instance".into(), true);
        capture(&other, "older.example", Some(source));
        capture(&other, "newer.example", Some(source));
        assert!(other.page(filter(), 1, Some(cursor), &id).is_err());
        store.set_limit(1);
        assert!(store.page(filter(), 1, Some(cursor), &id).is_err());
        assert_eq!(value(store.page_for_test()).await["total"], 1);
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_diagnostic_and_background_calls_do_not_enter_history() {
        let owner =
            crate::native_api::observation::NativeObservation::new(&honk_config::Config::default());
        let store = owner.dns.log_for_test();
        capture(store, "disabled.example", None);
        owner.settings.renew(&owner, false);
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
        tokio::time::advance(Duration::from_secs(60)).await;
        owner.settings.maintain(&owner);
        assert!(!store.recording());
        owner.settings.renew(&owner, false);
        assert!(store.recording());
        assert_eq!(value(store.page_for_test()).await["total"], 0);
    }

    #[tokio::test]
    async fn byte_eviction_retains_whole_unknown_records_and_never_clips_projection() {
        let store = LogStore::new("instance".into(), true);
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
        assert_eq!(
            store
                .page(Filter::default(), 3, None, &id)
                .unwrap_err()
                .into_response()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
