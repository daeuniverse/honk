//! One sampler's bounded, process-local memory and traffic observations.

use std::{
    collections::VecDeque,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use axum::{
    Json,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::json;
use tokio::io::AsyncReadExt;

use super::{
    ApiError, ErrorCode, NativeState, error, invalid_query, parse_query, timestamp,
    types::{RequestId, TrafficSummary},
};
use crate::observe::MAX_SAFE_UINT;

pub(super) const RETENTION: Duration = Duration::from_secs(600);
pub(super) const MAX_POINTS: usize = 600;

pub(crate) struct Telemetry {
    state: Mutex<Samples>,
}

struct Samples {
    latest: MemoryReading,
    metrics: Vec<&'static str>,
    traffic: Option<VecDeque<Sample<TrafficPoint>>>,
    memory: Option<VecDeque<Sample<MemoryPoint>>>,
}

impl Samples {
    fn learn(&mut self, reading: &MemoryReading) {
        for metric in reading.metrics() {
            if !self.metrics.contains(&metric) {
                self.metrics.push(metric);
            }
        }
    }
}

struct Sample<T> {
    at: SystemTime,
    recorded: Instant,
    value: T,
}

#[derive(Clone, Serialize)]
struct TrafficPoint {
    sampled_at: String,
    upload_bytes_per_second: Option<String>,
    download_bytes_per_second: Option<String>,
    connections: Option<u64>,
}

#[derive(Clone, Serialize)]
struct MemoryPoint {
    sampled_at: String,
    rss_bytes: Option<String>,
    cgroup_current_bytes: Option<String>,
    kernel_ebpf_bytes: Option<String>,
}

#[derive(Default)]
struct MemoryReading {
    rss: Option<u64>,
    cgroup: Option<CgroupReading>,
    ebpf: Option<(u64, SystemTime)>,
}

struct CgroupReading {
    scope: &'static str,
    current: Option<u64>,
    limit: Option<u64>,
    limit_readable: bool,
    events: [Option<u64>; 3],
}

impl Telemetry {
    pub(crate) fn new(record_traffic: bool, record_memory: bool) -> Self {
        Self {
            state: Mutex::new(Samples {
                latest: MemoryReading::default(),
                metrics: Vec::new(),
                traffic: record_traffic.then(VecDeque::new),
                memory: record_memory.then(VecDeque::new),
            }),
        }
    }

    pub(crate) fn record_traffic(&self) -> bool {
        self.state.lock().traffic.is_some()
    }
    pub(crate) fn record_memory(&self) -> bool {
        self.state.lock().memory.is_some()
    }
    pub(crate) fn metrics(&self) -> Vec<&'static str> {
        self.state.lock().metrics.clone()
    }

    /// Fixes the readable metric names before the first sample, so capabilities do not start empty.
    pub(super) async fn discover(&self) {
        let reading = read_memory(Path::new("/proc/self")).await;
        self.state.lock().learn(&reading);
    }

    pub(super) async fn sample(&self, traffic: &TrafficSummary) {
        let reading = read_memory(Path::new("/proc/self")).await;
        let at = SystemTime::now();
        self.record(traffic, reading, at, Instant::now());
    }

    fn record(
        &self,
        traffic: &TrafficSummary,
        reading: MemoryReading,
        at: SystemTime,
        now: Instant,
    ) {
        let mut samples = self.state.lock();
        samples.learn(&reading);
        if let Some(ring) = &mut samples.traffic {
            prune(ring, now);
            if let Some(sampled_at) = &traffic.sampled_at
                && let Ok(sample_time) = chrono::DateTime::parse_from_rfc3339(sampled_at)
            {
                push(
                    ring,
                    Sample {
                        at: sample_time.into(),
                        recorded: now,
                        value: TrafficPoint {
                            sampled_at: sampled_at.clone(),
                            upload_bytes_per_second: traffic
                                .rates
                                .as_ref()
                                .and_then(|rates| rates.upload_bytes_per_second.clone()),
                            download_bytes_per_second: traffic
                                .rates
                                .as_ref()
                                .and_then(|rates| rates.download_bytes_per_second.clone()),
                            connections: traffic
                                .connections
                                .total
                                .filter(|value| *value <= MAX_SAFE_UINT),
                        },
                    },
                );
            }
        }
        if let Some(ring) = &mut samples.memory {
            prune(ring, now);
            push(
                ring,
                Sample {
                    at,
                    recorded: now,
                    value: MemoryPoint {
                        sampled_at: timestamp(at),
                        rss_bytes: reading.rss.map(|value| value.to_string()),
                        cgroup_current_bytes: reading
                            .cgroup
                            .as_ref()
                            .and_then(|cgroup| cgroup.current)
                            .map(|value| value.to_string()),
                        kernel_ebpf_bytes: reading.ebpf.map(|(bytes, _)| bytes.to_string()),
                    },
                },
            );
        }
        samples.latest = reading;
    }
}

fn prune<T>(ring: &mut VecDeque<Sample<T>>, now: Instant) {
    while ring
        .front()
        .is_some_and(|sample| now.saturating_duration_since(sample.recorded) >= RETENTION)
    {
        ring.pop_front();
    }
}

fn push<T>(ring: &mut VecDeque<Sample<T>>, sample: Sample<T>) {
    if ring.len() == MAX_POINTS {
        ring.pop_front();
    }
    ring.push_back(sample);
}

fn history<T: Clone>(
    ring: &VecDeque<Sample<T>>,
    observed_at: SystemTime,
    window: u64,
    max_points: usize,
) -> (usize, Vec<T>) {
    let start = observed_at
        .checked_sub(Duration::from_secs(window))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut selected: Vec<_> = ring
        .iter()
        .filter(|sample| sample.at > start && sample.at <= observed_at)
        .collect();
    // Wall-clock corrections must not invert the contract's oldest-first order.
    selected.sort_by_key(|sample| sample.at);
    let stride = selected.len().div_ceil(max_points).max(1);
    let mut values: Vec<_> = selected
        .into_iter()
        .rev()
        .step_by(stride)
        .map(|sample| sample.value.clone())
        .collect();
    values.reverse();
    (stride, values)
}

fn history_query(uri: &Uri, id: &RequestId) -> Result<(u64, usize), ApiError> {
    let values = parse_query(uri, &["window_seconds", "max_points"], id)?;
    let number = |name: &str, max: usize| -> Result<usize, ApiError> {
        let Some(value) = values.get(name) else {
            return Ok(max);
        };
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid_query(id));
        }
        let value = value.parse::<usize>().map_err(|_| invalid_query(id))?;
        if !(1..=max).contains(&value) {
            return Err(invalid_query(id));
        }
        Ok(value)
    };
    Ok((
        number("window_seconds", RETENTION.as_secs() as usize)? as u64,
        number("max_points", MAX_POINTS)?,
    ))
}

fn disabled(id: &RequestId) -> ApiError {
    error(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "History recording is disabled",
        id,
    )
}

pub(super) async fn traffic_history(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let telemetry = &state.observation.telemetry;
    if !telemetry.record_traffic() {
        return Err(disabled(id));
    }
    let (window, points) = history_query(uri, id)?;
    let observed_at = SystemTime::now();
    let mut samples = telemetry.state.lock();
    let ring = samples.traffic.as_mut().ok_or_else(|| disabled(id))?;
    prune(ring, Instant::now());
    let (stride, values) = history(ring, observed_at, window, points);
    Ok(Json(json!({"observed_at": timestamp(observed_at), "window_seconds": window, "sampled_every_seconds": stride, "samples": values})).into_response())
}

pub(super) async fn memory_history(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let telemetry = &state.observation.telemetry;
    if !telemetry.record_memory() {
        return Err(disabled(id));
    }
    let (window, points) = history_query(uri, id)?;
    let observed_at = SystemTime::now();
    let mut samples = telemetry.state.lock();
    let ring = samples.memory.as_mut().ok_or_else(|| disabled(id))?;
    prune(ring, Instant::now());
    let (stride, values) = history(ring, observed_at, window, points);
    Ok(Json(json!({"observed_at": timestamp(observed_at), "window_seconds": window, "sampled_every_seconds": stride, "samples": values})).into_response())
}

pub(super) async fn memory(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let samples = state.observation.telemetry.state.lock();
    let reading = &samples.latest;
    let cgroup = reading.cgroup.as_ref().map(|value| json!({
        "scope": value.scope,
        "current_bytes": value.current.map(|value| value.to_string()),
        "limit_bytes": value.limit.map(|value| value.to_string()),
        "events": {"high": value.events[0].map(|value| value.to_string()), "oom": value.events[1].map(|value| value.to_string()), "oom_kill": value.events[2].map(|value| value.to_string())},
    }));
    let kernel = reading
        .ebpf
        .map(|(bytes, at)| json!({"ebpf_bytes": bytes.to_string(), "sampled_at": timestamp(at)}));
    Ok(Json(json!({
        "observed_at": timestamp(SystemTime::now()),
        "process": {"rss_bytes": reading.rss.map(|value| value.to_string())},
        "cgroup": cgroup, "kernel": kernel,
    }))
    .into_response())
}

pub(super) async fn outbounds(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let rows = state.stats.native_snapshot().into_iter().map(|row| {
        // Unlike cumulative UInt64 fields, active connections are a SafeUInt.
        if row.active_connections > MAX_SAFE_UINT {
            return Err(error(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::TemporarilyUnavailable, "Outbound active counter is not representable", id));
        }
        Ok(json!({
            "name": row.name, "kind": row.kind.as_str(), "active_connections": row.active_connections,
            "total_connections": row.total_connections.to_string(), "upload_bytes": row.upload_bytes.to_string(),
            "download_bytes": row.download_bytes.to_string(), "errors": row.errors.to_string(),
        }))
    }).collect::<Result<Vec<_>, ApiError>>()?;
    let value = super::config::administrative_projection(
        state,
        json!({"observed_at": timestamp(SystemTime::now()), "counter_since": timestamp(state.stats.counter_since()), "outbounds": rows}),
    )?;
    Ok(Json(value).into_response())
}

impl MemoryReading {
    fn metrics(&self) -> impl Iterator<Item = &'static str> {
        let cgroup = self.cgroup.as_ref();
        [
            self.rss.is_some().then_some("process.rss_bytes"),
            cgroup
                .is_some_and(|group| group.current.is_some())
                .then_some("cgroup.current_bytes"),
            cgroup
                .is_some_and(|group| group.limit_readable)
                .then_some("cgroup.limit_bytes"),
            cgroup
                .is_some_and(|group| group.events[0].is_some())
                .then_some("cgroup.events.high"),
            cgroup
                .is_some_and(|group| group.events[1].is_some())
                .then_some("cgroup.events.oom"),
            cgroup
                .is_some_and(|group| group.events[2].is_some())
                .then_some("cgroup.events.oom_kill"),
            self.ebpf.is_some().then_some("kernel.ebpf_bytes"),
        ]
        .into_iter()
        .flatten()
    }
}

async fn bounded_read(path: impl AsRef<Path>, limit: usize) -> Option<String> {
    let file = tokio::fs::File::open(path).await.ok()?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .ok()?;
    if bytes.len() > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn unsigned(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn rss(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        unsigned(line.strip_prefix("VmRSS:")?.trim().strip_suffix(" kB")?)?.checked_mul(1024)
    })
}

fn mount_path(value: &str) -> Option<PathBuf> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut source = value.as_bytes().iter().copied();
    while let Some(byte) = source.next() {
        bytes.push(if byte == b'\\' {
            match [source.next()?, source.next()?, source.next()?] {
                [b'0', b'4', b'0'] => b' ',
                [b'0', b'1', b'1'] => b'\t',
                [b'0', b'1', b'2'] => b'\n',
                [b'1', b'3', b'4'] => b'\\',
                _ => return None,
            }
        } else {
            byte
        });
    }
    use std::os::unix::ffi::OsStringExt;
    let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
    safe_absolute(&path).then_some(path)
}

fn safe_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn cgroup_directory(membership: &str, mountinfo: &str) -> Option<PathBuf> {
    let mut memberships = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"));
    let member = Path::new(memberships.next()?);
    if memberships.next().is_some() || !safe_absolute(member) {
        return None;
    }
    mountinfo
        .lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            if right.split_whitespace().next()? != "cgroup2" {
                return None;
            }
            let mut fields = left.split_whitespace();
            let root = mount_path(fields.nth(3)?)?;
            let mount = mount_path(fields.next()?)?;
            let relative = member.strip_prefix(&root).ok()?;
            Some((root.components().count(), mount.join(relative)))
        })
        .max_by_key(|(depth, _)| *depth)
        .map(|(_, path)| path)
}

fn cgroup_events(contents: &str) -> [Option<u64>; 3] {
    let mut result = [None; 3];
    for (index, name) in ["high", "oom", "oom_kill"].into_iter().enumerate() {
        let mut matching = contents.lines().filter_map(|line| {
            let mut words = line.split_whitespace();
            if words.next()? != name {
                return None;
            }
            let value = words.next().and_then(unsigned);
            Some(if words.next().is_none() { value } else { None })
        });
        result[index] = matching.next().flatten();
        if matching.next().is_some() {
            result[index] = None;
        }
    }
    result
}

/// `service` only when honk is alone in a leaf cgroup, so the cgroup's memory is honk's own.
async fn cgroup_scope(directory: &Path) -> &'static str {
    let Ok(file) = tokio::fs::File::open(directory.join("cgroup.procs")).await else {
        return "unknown";
    };
    // A lone PID line fits in 16 bytes; a longer file already lists another process.
    let mut head = Vec::new();
    if file.take(16).read_to_end(&mut head).await.is_err() || head.is_empty() {
        return "unknown";
    }
    if head != format!("{}\n", std::process::id()).into_bytes() {
        return "shared";
    }
    let Ok(mut entries) = tokio::fs::read_dir(directory).await else {
        return "unknown";
    };
    loop {
        match entries.next_entry().await {
            Ok(Some(entry)) if entry.file_type().await.is_ok_and(|kind| kind.is_dir()) => {
                return "shared";
            }
            Ok(Some(_)) => {}
            Ok(None) => return "service",
            Err(_) => return "unknown",
        }
    }
}

fn bpf_memlock(fdinfo: &str) -> Option<u64> {
    let bpf = fdinfo
        .lines()
        .any(|line| line.starts_with("map_type:") || line.starts_with("prog_type:"));
    bpf.then(|| {
        fdinfo
            .lines()
            .find_map(|line| unsigned(line.strip_prefix("memlock:")?))
    })?
}

/// Sums the memlock charged to this process's own BPF maps and programs; needs no BTF.
fn ebpf_bytes(proc_self: &Path) -> Option<u64> {
    let fdinfo = proc_self.join("fdinfo");
    std::fs::read_dir(proc_self.join("fd"))
        .ok()?
        .flatten()
        .filter(|entry| {
            std::fs::read_link(entry.path()).is_ok_and(|target| {
                matches!(
                    target.to_str(),
                    Some("anon_inode:bpf-map" | "anon_inode:bpf-prog")
                )
            })
        })
        .filter_map(|entry| {
            bpf_memlock(&std::fs::read_to_string(fdinfo.join(entry.file_name())).ok()?)
        })
        .reduce(u64::saturating_add)
}

async fn read_memory(proc_self: &Path) -> MemoryReading {
    let fds = proc_self.to_path_buf();
    let (status, membership, mounts, ebpf) = tokio::join!(
        bounded_read(proc_self.join("status"), 64 * 1024),
        bounded_read(proc_self.join("cgroup"), 64 * 1024),
        bounded_read(proc_self.join("mountinfo"), 256 * 1024),
        tokio::task::spawn_blocking(
            move || ebpf_bytes(&fds).map(|bytes| (bytes, SystemTime::now()))
        ),
    );
    let mut reading = MemoryReading {
        rss: status.as_deref().and_then(rss),
        cgroup: None,
        ebpf: ebpf.ok().flatten(),
    };
    let Some(directory) = membership
        .as_deref()
        .zip(mounts.as_deref())
        .and_then(|(membership, mounts)| cgroup_directory(membership, mounts))
    else {
        return reading;
    };
    let (current, limit, events, scope) = tokio::join!(
        bounded_read(directory.join("memory.current"), 128),
        bounded_read(directory.join("memory.max"), 128),
        bounded_read(directory.join("memory.events"), 16 * 1024),
        cgroup_scope(&directory),
    );
    let current = current.as_deref().and_then(unsigned);
    let limit_value = limit.as_deref().and_then(unsigned);
    let limit_readable =
        limit_value.is_some() || limit.as_deref().is_some_and(|value| value.trim() == "max");
    let events = events.as_deref().map(cgroup_events).unwrap_or([None; 3]);
    if current.is_some() || limit_readable || events.iter().any(Option::is_some) {
        reading.cgroup = Some(CgroupReading {
            scope,
            current,
            limit: limit_value,
            limit_readable,
            events,
        });
    }
    reading
}

#[cfg(test)]
mod tests;
