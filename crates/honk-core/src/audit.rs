//! Best-effort client DNS audit, independent of API observation and log filters.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::dns::outcome::DnsOutcome;
use crate::dns::query::IngressProfile;
use crate::dns::response::presentation;

const QUEUE_LEN: usize = 1024;
const QUEUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;
const WIRE_LIMIT: usize = u16::MAX as usize;

mod transport;
pub(crate) use transport::DnsAuditWorker;

#[derive(Clone)]
struct Identity {
    hostname: String,
    app_name: String,
}

impl Identity {
    fn from_config(global: &honk_config::config::GlobalConfig) -> Self {
        let hostname = if global.syslog_hostname.is_empty() {
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .ok()
                .map(|name| Self::system_hostname(&name))
                .unwrap_or_else(|| "-".into())
        } else {
            global.syslog_hostname.clone()
        };
        Self {
            hostname,
            app_name: global.syslog_app_name.clone(),
        }
    }

    fn system_hostname(name: &str) -> String {
        let name = name.strip_suffix('\n').unwrap_or(name);
        if honk_config::check::valid_syslog_header_field(name, 255) {
            name.into()
        } else {
            "-".into()
        }
    }

    fn header(&self, time: SystemTime, cee: bool) -> String {
        format!(
            "<134>1 {} {} {} - dns.query - {}",
            timestamp(time),
            self.hostname,
            self.app_name,
            if cee { "@cee: " } else { "" }
        )
    }
}

#[derive(Default)]
struct Counters {
    dropped: AtomicU64,
    invalid: AtomicU64,
    send_failed: AtomicU64,
    connect_failed: AtomicU64,
    submitted: AtomicU64,
}

#[derive(Clone, Default)]
pub(crate) struct DnsAudit {
    sender: Option<mpsc::Sender<Entry>>,
    admission: Arc<Admission>,
}

struct Admission {
    counters: Counters,
    bytes: Arc<Semaphore>,
    stopped: std::sync::atomic::AtomicBool,
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            counters: Counters::default(),
            bytes: Arc::new(Semaphore::new(QUEUE_BYTES)),
            stopped: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

struct Entry {
    started: SystemTime,
    completed: SystemTime,
    duration: Duration,
    upstream: Option<Box<str>>,
    source: SocketAddr,
    ingress: IngressProfile,
    query: Box<[u8]>,
    response: Option<Box<[u8]>>,
    _query_memory: Option<OwnedSemaphorePermit>,
    _response_memory: Option<OwnedSemaphorePermit>,
}

pub(crate) struct DnsAuditQuery {
    started: tokio::time::Instant,
    admission: Arc<Admission>,
    permit: Option<mpsc::OwnedPermit<Entry>>,
    entry: Option<Entry>,
}

impl DnsAudit {
    pub(crate) fn begin_udp(&self, query: &[u8], source: SocketAddr) -> Option<DnsAuditQuery> {
        self.sender.as_ref()?;
        let ingress = crate::dns::query::validate_exact_dns_query(query).map_or(
            IngressProfile::Udp {
                advertised_size: 512,
            },
            |query| query.ingress(),
        );
        self.begin(query, ingress, source)
    }

    pub(crate) fn begin(
        &self,
        query: &[u8],
        ingress: IngressProfile,
        source: SocketAddr,
    ) -> Option<DnsAuditQuery> {
        let sender = self.sender.as_ref()?;
        if self.admission.stopped.load(Ordering::Acquire) {
            return None;
        }
        if query.len() > WIRE_LIMIT {
            self.admission
                .counters
                .invalid
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let permit = match sender.clone().try_reserve_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.admission
                    .counters
                    .dropped
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        let query_memory = match Arc::clone(&self.admission.bytes)
            .try_acquire_many_owned((query.len() + size_of::<Entry>()) as u32)
        {
            Ok(memory) => memory,
            Err(_) => {
                self.admission
                    .counters
                    .dropped
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        let started = SystemTime::now();
        Some(DnsAuditQuery {
            started: tokio::time::Instant::now(),
            admission: Arc::clone(&self.admission),
            permit: Some(permit),
            entry: Some(Entry {
                started,
                completed: started,
                duration: Duration::ZERO,
                upstream: None,
                source,
                ingress,
                query: query.into(),
                response: None,
                _query_memory: Some(query_memory),
                _response_memory: None,
            }),
        })
    }
}

impl DnsAuditQuery {
    pub(crate) fn discard(mut self) {
        self.entry.take();
        self.permit.take();
    }

    pub(crate) fn finish(mut self, response: &[u8], outcome: Option<&DnsOutcome>) {
        let completed = (SystemTime::now(), self.started.elapsed());
        let upstream = outcome.and_then(|outcome| {
            if outcome.is_cached() {
                Some("cache")
            } else {
                outcome.final_upstream()
            }
        });
        let memory = response
            .len()
            .checked_add(upstream.map_or(0, str::len))
            .filter(|_| response.len() <= WIRE_LIMIT)
            .and_then(|bytes| u32::try_from(bytes).ok())
            .and_then(|bytes| {
                Arc::clone(&self.admission.bytes)
                    .try_acquire_many_owned(bytes)
                    .ok()
            });
        let Some(memory) = memory else {
            self.admission
                .counters
                .dropped
                .fetch_add(1, Ordering::Relaxed);
            self.entry.take();
            self.permit.take();
            return;
        };
        if let Some(entry) = self.entry.as_mut() {
            entry.response = Some(response.into());
            entry.upstream = upstream.map(Into::into);
            entry._response_memory = Some(memory);
        }
        self.publish(completed);
    }

    fn publish(&mut self, completed: (SystemTime, Duration)) {
        if let (Some(permit), Some(mut entry)) = (self.permit.take(), self.entry.take()) {
            if self.admission.stopped.load(Ordering::Acquire) {
                self.admission
                    .counters
                    .dropped
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            entry.completed = completed.0;
            entry.duration = completed.1;
            permit.send(entry);
        }
    }
}

impl Drop for DnsAuditQuery {
    fn drop(&mut self) {
        if self.entry.is_some() {
            self.publish((SystemTime::now(), self.started.elapsed()));
        }
    }
}

fn timestamp(time: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn encode(
    entry: &Entry,
    id: &str,
    identity: &Identity,
) -> Result<serde_json::Value, presentation::ProjectionError> {
    let question = presentation::question(&entry.query, entry.ingress)?;
    let mut budget = MAX_EVENT_BYTES;
    let answers = entry
        .response
        .as_deref()
        .map(|response| presentation::project(&entry.query, response, entry.ingress, &mut budget))
        .transpose()?
        .unwrap_or_default();
    let (answer_ips, answer_cnames, answer_types) = answer_indexes(&answers);
    let client_ip = entry.source.ip().to_canonical();
    let rcode = entry.response.as_deref().map(presentation::status);
    let message = format!(
        "DNS {} {} {} {}: {} answers={}",
        client_ip,
        question.name,
        question.rtype,
        question.class,
        rcode.as_deref().unwrap_or("cancelled"),
        answers.len()
    );
    Ok(json!({
        "schema_version": 1, "event": "dns.query", "event_id": id,
        "message": message,
        "hostname": identity.hostname, "app_name": identity.app_name,
        "query_time": timestamp(entry.started), "completed_at": timestamp(entry.completed),
        "duration_ms": entry.duration.as_micros() as f64 / 1000.0,
        "upstream": entry.upstream,
        "client_ip": client_ip, "client_port": entry.source.port(),
        "transport": match entry.ingress { IngressProfile::Tcp => "tcp", _ => "udp" },
        "domain": question.name, "qtype": question.rtype, "qclass": question.class,
        "result": if entry.response.is_some() { "response" } else { "cancelled" },
        "rcode": rcode,
        "response_truncated": entry.response.as_deref().is_some_and(crate::dns::response::is_truncated),
        "answers": answers,
        "answer_ips": answer_ips, "answer_cnames": answer_cnames, "answer_types": answer_types
    }))
}

fn answer_indexes(answers: &[presentation::DnsAnswer]) -> (Vec<&str>, Vec<&str>, Vec<&str>) {
    let mut ips = Vec::new();
    let mut cnames = Vec::new();
    let mut types = Vec::new();
    let mut seen_ips = std::collections::HashSet::new();
    let mut seen_cnames = std::collections::HashSet::new();
    let mut seen_types = std::collections::HashSet::new();
    for answer in answers {
        if seen_types.insert(answer.rtype.as_str()) {
            types.push(answer.rtype.as_str());
        }
        match answer.rtype.as_str() {
            "A" | "AAAA" if seen_ips.insert(answer.data.as_str()) => ips.push(answer.data.as_str()),
            "CNAME" if seen_cnames.insert(answer.data.as_str()) => {
                cnames.push(answer.data.as_str())
            }
            _ => {}
        }
    }
    (ips, cnames, types)
}

struct LimitedMessage {
    bytes: Vec<u8>,
}

impl std::io::Write for LimitedMessage {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > MAX_EVENT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "audit event exceeds byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn frame(
    value: &serde_json::Value,
    time: SystemTime,
    identity: &Identity,
    cee: bool,
) -> std::io::Result<Vec<u8>> {
    let mut message = LimitedMessage { bytes: Vec::new() };
    std::io::Write::write_all(&mut message, identity.header(time, cee).as_bytes())?;
    serde_json::to_writer(&mut message, value).map_err(std::io::Error::other)?;
    let prefix = format!("{} ", message.bytes.len());
    let mut bytes = Vec::with_capacity(prefix.len() + message.bytes.len());
    bytes.extend_from_slice(prefix.as_bytes());
    bytes.extend_from_slice(&message.bytes);
    Ok(bytes)
}

#[cfg(test)]
pub(crate) mod tests;
