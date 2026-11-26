//! Bootstrap DNS resolution for proxy-server hostnames.
//!
//! Node dials must not depend on the regular DNS path: the system resolver
//! may itself be routed through honk (interception + DNS routing), so right
//! after a restart — before any node is reachable — resolving a proxy
//! server's domain can deadlock against the very nodes it is needed to
//! reach. dae solves this with `bootstrap_resolver`: a plain, direct DNS
//! server that honk queries itself on a bypass-marked socket.
//!
//! [`resolve`] first offers the host to the installed [`NodeHostResolver`],
//! which claims hosts aliases and node hosts explicitly routed by `subtag()`
//! to a direct upstream. Unclaimed hosts use the configured bootstrap resolver,
//! then `/etc/hosts` and the first numeric `/etc/resolv.conf` nameserver.
//! Every DNS socket is bypass-marked; libc NSS/search-suffix resolution is
//! deliberately not used.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

mod wire;

pub use wire::qtype_name;
use wire::{
    QTYPE_HTTPS, answers_query, build_query, merge_min_ttl, parse_answers, parse_https_rr_ech,
};

/// A direct DNS server used to resolve proxy-server hostnames.
#[derive(Debug, Clone, Copy)]
pub struct BootstrapResolver {
    server: SocketAddr,
    use_tcp: bool,
}

impl BootstrapResolver {
    /// Parse `8.8.8.8:53`, `udp://8.8.8.8:53` or `tcp://8.8.8.8:53`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (use_tcp, rest) = match s.split_once("://") {
            Some((scheme, rest)) => (scheme.eq_ignore_ascii_case("tcp"), rest),
            None => (false, s),
        };
        let server: SocketAddr = rest.parse().ok()?;
        Some(Self { server, use_tcp })
    }
}

static GLOBAL: RwLock<Option<BootstrapResolver>> = RwLock::new(None);

/// Install (or clear) the process-wide bootstrap resolver. Called by
/// honk-core at startup and on config reload.
pub fn set_global(resolver: Option<BootstrapResolver>) {
    *GLOBAL.write().unwrap() = resolver;
}

/// Snapshot the process-wide resolver for compatibility callers that do not
/// already own a configuration generation.
pub fn global() -> Option<BootstrapResolver> {
    match GLOBAL.read() {
        Ok(resolver) => *resolver,
        Err(poisoned) => *poisoned.into_inner(),
    }
}

/// The configured bootstrap resolver's server address, if any. Also used
/// as the `direct` node's probe/urltest target: a plain directly-reachable
/// DNS server is exactly what direct-egress latency should be measured
/// against.
pub fn global_server() -> Option<SocketAddr> {
    GLOBAL.read().unwrap().map(|r| r.server)
}

/// An authoritative node server host lookup.
pub type NodeHostLookup = futures_util::future::BoxFuture<'static, io::Result<Vec<IpAddr>>>;

/// Resolves node server hosts that configured DNS rules claim.
pub trait NodeHostResolver: Send + Sync {
    /// `None` leaves `host` to the bootstrap resolver. A returned lookup is
    /// authoritative: its failure is the dial's failure.
    fn lookup(&self, host: &str) -> Option<NodeHostLookup>;
}

static NODE_HOSTS: RwLock<Option<Arc<dyn NodeHostResolver>>> = RwLock::new(None);

/// Install (or clear) the process-wide node host resolver alongside
/// [`set_global`].
pub fn set_node_host_resolver(resolver: Option<Arc<dyn NodeHostResolver>>) {
    *NODE_HOSTS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = resolver;
}

/// Resolve `host`, preferring a claiming [`NodeHostResolver`], then the
/// configured bootstrap resolver, then `/etc/hosts` and bypass-marked queries
/// to the system nameserver.
pub async fn resolve(host: &str) -> io::Result<Vec<IpAddr>> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if crate::runtime::pinned_server_address(bare).is_none() && bare.parse::<IpAddr>().is_err() {
        let resolver = NODE_HOSTS
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(lookup) = resolver.and_then(|resolver| resolver.lookup(bare)) {
            return lookup.await;
        }
    }
    resolve_with(global(), host).await
}

/// Address families requested from a bootstrap DNS lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryFamilies {
    /// Query A and AAAA concurrently; `prefer_v6` selects which family gets the
    /// longer completion window when the other answers first.
    Both { prefer_v6: bool },
    /// Query only IPv4 (A) records.
    Ipv4Only,
    /// Query only IPv6 (AAAA) records.
    Ipv6Only,
}

impl QueryFamilies {
    fn matches(self, ip: IpAddr) -> bool {
        match self {
            Self::Both { .. } => true,
            Self::Ipv4Only => ip.is_ipv4(),
            Self::Ipv6Only => ip.is_ipv6(),
        }
    }
}

/// Addresses and minimum answer TTL returned by a bootstrap lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRecords {
    pub ips: Vec<IpAddr>,
    pub min_ttl: Option<u32>,
}

/// Resolve with an explicit resolver snapshot.
///
/// Generation-owned callers use this path so a later [`set_global`] cannot
/// change the resolver selected by an in-flight or lazily initialized dial.
pub async fn resolve_with(
    resolver: Option<BootstrapResolver>,
    host: &str,
) -> io::Result<Vec<IpAddr>> {
    Ok(resolve_with_inner(
        resolver,
        host,
        QueryFamilies::Both { prefer_v6: false },
        None,
        || std::future::ready(Ok(())),
    )
    .await?
    .ips)
}

/// Resolve with socket admission, explicit address families, and minimum answer TTL.
/// Local answers need no guard; admission errors never trigger resolver fallback.
pub fn resolve_records_with_admission<'a, Admit, Admission, Guard>(
    resolver: Option<BootstrapResolver>,
    host: &'a str,
    families: QueryFamilies,
    deadline: tokio::time::Instant,
    admit: Admit,
) -> impl Future<Output = io::Result<ResolvedRecords>> + use<'a, Admit, Admission, Guard>
where
    Admit: FnMut() -> Admission,
    Admission: Future<Output = io::Result<Guard>>,
{
    resolve_with_inner(resolver, host, families, Some(deadline), admit)
}

async fn resolve_with_inner<Admit, Admission, Guard>(
    resolver: Option<BootstrapResolver>,
    host: &str,
    families: QueryFamilies,
    deadline: Option<tokio::time::Instant>,
    mut admit: Admit,
) -> io::Result<ResolvedRecords>
where
    Admit: FnMut() -> Admission,
    Admission: Future<Output = io::Result<Guard>>,
{
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Some(ip) = crate::runtime::pinned_server_address(host) {
        return Ok(ResolvedRecords {
            ips: vec![ip],
            min_ttl: None,
        });
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ResolvedRecords {
            ips: vec![ip],
            min_ttl: None,
        });
    }
    let mut configured_error: Option<io::Error> = None;
    if let Some(resolver) = resolver {
        let result = {
            let _guard = admit().await?;
            resolver.query_records(host, families, deadline).await
        };
        match result {
            Ok(records) if !records.ips.is_empty() => return Ok(records),
            Ok(_) => tracing::debug!("bootstrap resolver returned no records for '{}'", host),
            Err(e) => {
                tracing::debug!("bootstrap resolution of '{}' failed: {}", host, e);
                configured_error = Some(e);
            }
        }
    }
    if let Ok(contents) = tokio::fs::read_to_string("/etc/hosts").await {
        let mut addrs = hosts_addresses(&contents, host);
        addrs.retain(|ip| families.matches(*ip));
        if !addrs.is_empty() {
            if let Some(mut observation) =
                LookupObservation::start(host, "UNKNOWN", LookupOrigin::Hosts)
            {
                observation.finish(Ok::<_, &io::Error>(addrs.iter().copied()));
            }
            return Ok(ResolvedRecords {
                ips: addrs,
                min_ttl: None,
            });
        }
    }
    // Short-circuit after local /etc/hosts lookup and again after reading
    // /etc/resolv.conf so an expired deadline never invokes admit() -> Capacity.
    if let Some(err) = deadline_expired_error(deadline, &mut configured_error) {
        return Err(err);
    }
    let server = system_nameserver().await.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no numeric system DNS nameserver")
    })?;
    if let Some(err) = deadline_expired_error(deadline, &mut configured_error) {
        return Err(err);
    }
    let resolver = BootstrapResolver {
        server,
        use_tcp: false,
    };
    let _guard = admit().await?;
    let records = resolver.query_records(host, families, deadline).await?;
    if records.ips.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no DNS addresses"));
    }
    Ok(records)
}

fn deadline_expired_error(
    deadline: Option<tokio::time::Instant>,
    configured_error: &mut Option<io::Error>,
) -> Option<io::Error> {
    let deadline = deadline?;
    if tokio::time::Instant::now() < deadline {
        return None;
    }
    Some(match configured_error.take() {
        Some(err) if err.kind() == io::ErrorKind::TimedOut => err,
        _ => io::Error::new(
            io::ErrorKind::TimedOut,
            "bootstrap DNS resolution timed out",
        ),
    })
}

fn hosts_addresses(contents: &str, host: &str) -> Vec<IpAddr> {
    let mut addrs = Vec::new();
    let host = host.trim_end_matches('.');
    for line in contents.lines() {
        let mut fields = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_ascii_whitespace();
        let Some(ip) = fields.next().and_then(|ip| ip.parse::<IpAddr>().ok()) else {
            continue;
        };
        if fields.any(|name| name.trim_end_matches('.').eq_ignore_ascii_case(host))
            && !addrs.contains(&ip)
        {
            addrs.push(ip);
        }
    }
    addrs
}

/// Budget for one address family's exchange, connect included.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Stepped UDP retransmit offsets from the initial send (3 sends total).
/// The 400 ms initial wait clears typical WAN RTTs before resending.
const UDP_RETRANSMIT_OFFSETS: [Duration; 2] =
    [Duration::from_millis(400), Duration::from_millis(1200)];
/// Completion cap for the non-preferred family after the preferred family returns IPs.
const PREFERRED_FIRST_COMPLETION_WINDOW: Duration = Duration::from_millis(500);
/// Completion cap for the preferred family after the non-preferred family returns IPs
/// (wide enough to cover the first 400ms UDP retransmit plus RTT).
const SECONDARY_FIRST_COMPLETION_WINDOW: Duration = Duration::from_millis(1000);

impl BootstrapResolver {
    /// Boxed on the network path so callers embedding `bootstrap::resolve`
    /// do not carry dual-stack and retry future state on their own stack frames.
    fn query_records<'a>(
        &'a self,
        host: &'a str,
        families: QueryFamilies,
        deadline: Option<tokio::time::Instant>,
    ) -> futures_util::future::BoxFuture<'a, io::Result<ResolvedRecords>> {
        let now = tokio::time::Instant::now();
        if let Some(deadline) = deadline
            && now >= deadline
        {
            return Box::pin(std::future::ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "bootstrap DNS resolution timed out",
            ))));
        }
        let cap = match deadline {
            Some(deadline) => deadline.min(now + QUERY_TIMEOUT),
            None => now + QUERY_TIMEOUT,
        };
        match families {
            QueryFamilies::Both { prefer_v6 } => Box::pin(self.query_both(host, prefer_v6, cap)),
            QueryFamilies::Ipv4Only => Box::pin(self.query_family(host, 1, cap)),
            QueryFamilies::Ipv6Only => Box::pin(self.query_family(host, 28, cap)),
        }
    }

    async fn query_both(
        &self,
        host: &str,
        prefer_v6: bool,
        cap: tokio::time::Instant,
    ) -> io::Result<ResolvedRecords> {
        let (preferred_qtype, secondary_qtype) = if prefer_v6 { (28, 1) } else { (1, 28) };
        let preferred = self.query_family(host, preferred_qtype, cap);
        let secondary = self.query_family(host, secondary_qtype, cap);
        tokio::pin!(preferred);
        tokio::pin!(secondary);

        enum First {
            Preferred(io::Result<ResolvedRecords>),
            Secondary(io::Result<ResolvedRecords>),
        }

        let first = tokio::select! {
            res = &mut preferred => First::Preferred(res),
            res = &mut secondary => First::Secondary(res),
        };

        // Drive both families without an outer timeout_at so a non-empty answer
        // from either family is never discarded if the other stalls until deadline.
        let (pref_res, sec_res) = match first {
            First::Preferred(pref_res) => {
                let sec_res = wait_remaining_family(
                    &pref_res,
                    secondary,
                    cap,
                    PREFERRED_FIRST_COMPLETION_WINDOW,
                )
                .await;
                (pref_res, sec_res)
            }
            First::Secondary(sec_res) => {
                let pref_res = wait_remaining_family(
                    &sec_res,
                    preferred,
                    cap,
                    SECONDARY_FIRST_COMPLETION_WINDOW,
                )
                .await;
                (pref_res, sec_res)
            }
        };

        merge_family_results(pref_res, sec_res)
    }

    /// Query A and AAAA records for `host` directly from the configured
    /// server over bypass-marked sockets, without a system-resolver fallback.
    pub async fn query(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        Ok(self
            .query_records(host, QueryFamilies::Both { prefer_v6: false }, None)
            .await?
            .ips)
    }

    async fn query_family(
        &self,
        host: &str,
        qtype: u16,
        deadline: tokio::time::Instant,
    ) -> io::Result<ResolvedRecords> {
        let mut observation = LookupObservation::start(
            host,
            qtype_name(qtype),
            LookupOrigin::Upstream(self.server, if self.use_tcp { "tcp" } else { "udp" }),
        );
        let child = observation.as_ref().map(LookupObservation::child);
        let result = async {
            let msg = self
                .query_raw(host, qtype, deadline, observation.as_mut())
                .await?;
            parse_answers(&msg, qtype)
        };
        let result = match child {
            Some(child) => child.scope(result).await,
            None => result.await,
        };
        if let Some(observation) = &mut observation {
            observation.finish(result.as_ref().map(|records| records.ips.iter().copied()));
        }
        result
    }

    /// Send a single query bounded by `deadline` and return the matching raw response.
    async fn query_raw(
        &self,
        host: &str,
        qtype: u16,
        deadline: tokio::time::Instant,
        observation: Option<&mut LookupObservation>,
    ) -> io::Result<Vec<u8>> {
        let query = build_query(host, qtype);
        tokio::time::timeout_at(deadline, async {
            if !self.use_tcp {
                let response = self.exchange_udp(&query).await?;
                // A truncated answer may omit records; libc's resolver retries it over TCP.
                if response[2] & 0x02 == 0 {
                    return Ok(response);
                }
                if let Some(observation) = observation {
                    observation.data.upstream_transport = Some("tcp");
                    observation.data.carrier_transport = Some("tcp");
                }
            }
            self.exchange_tcp(&query, deadline).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bootstrap DNS query timed out"))?
    }

    async fn exchange_tcp(
        &self,
        query: &[u8],
        deadline: tokio::time::Instant,
    ) -> io::Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "bootstrap DNS query timed out",
            ));
        }
        let mut stream = crate::util::connect_marked_addr(
            self.server,
            Some(crate::util::bypass_mark()),
            remaining,
        )
        .await?;
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(query).await?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        if !answers_query(query, &buf) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response does not match query",
            ));
        }
        Ok(buf)
    }

    async fn exchange_udp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let bind: SocketAddr = if self.server.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = crate::util::udp_marked_bind(bind).await?;
        socket.connect(self.server).await?;
        let started = tokio::time::Instant::now();
        socket.send(query).await?;
        let mut buf = vec![0u8; 1500];
        let mut retry_idx = 0usize;
        // Fixed absolute deadline outside the recv loop so spoofed/mismatched
        // datagrams skipped by recv never reset or starve retransmits.
        let retransmit = tokio::time::sleep_until(started + UDP_RETRANSMIT_OFFSETS[0]);
        tokio::pin!(retransmit);
        loop {
            tokio::select! {
                biased;
                () = &mut retransmit, if retry_idx < UDP_RETRANSMIT_OFFSETS.len() => {
                    socket.send(query).await?;
                    retry_idx += 1;
                    if let Some(&offset) = UDP_RETRANSMIT_OFFSETS.get(retry_idx) {
                        retransmit.as_mut().reset(started + offset);
                    }
                }
                res = socket.recv(&mut buf) => {
                    let n = res?;
                    if answers_query(query, &buf[..n]) {
                        buf.truncate(n);
                        return Ok(buf);
                    }
                }
            }
        }
    }
}

async fn wait_remaining_family<F>(
    first: &io::Result<ResolvedRecords>,
    remaining: F,
    cap: tokio::time::Instant,
    window: Duration,
) -> io::Result<ResolvedRecords>
where
    F: Future<Output = io::Result<ResolvedRecords>>,
{
    match first {
        Ok(rec) if !rec.ips.is_empty() => {
            let wait_until = cap.min(tokio::time::Instant::now() + window);
            tokio::time::timeout_at(wait_until, remaining)
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "bootstrap DNS completion window elapsed",
                    ))
                })
        }
        _ => remaining.await,
    }
}

fn merge_family_results(
    preferred: io::Result<ResolvedRecords>,
    secondary: io::Result<ResolvedRecords>,
) -> io::Result<ResolvedRecords> {
    match (preferred, secondary) {
        (Ok(mut pref), Ok(sec)) => {
            pref.ips.extend(sec.ips);
            pref.min_ttl = merge_min_ttl(pref.min_ttl, sec.min_ttl);
            Ok(pref)
        }
        (Ok(pref), Err(_)) if !pref.ips.is_empty() => Ok(pref),
        (Err(_), Ok(sec)) if !sec.ips.is_empty() => Ok(sec),
        (Err(e), _) | (_, Err(e)) => Err(e),
    }
}

/// First nameserver from /etc/resolv.conf (UDP, port 53). Used for record
/// lookups (e.g. ECH discovery) when no `bootstrap_resolver` is configured.
async fn system_nameserver() -> Option<SocketAddr> {
    let contents = tokio::fs::read_to_string("/etc/resolv.conf").await.ok()?;
    for line in contents.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() == Some("nameserver")
            && let Some(ip) = fields.next().and_then(|ip| ip.parse::<IpAddr>().ok())
        {
            return Some(SocketAddr::new(ip, 53));
        }
    }
    None
}

/// Look up the ECHConfigList for `host` via DNS HTTPS records (RFC 9460).
///
/// Queries the configured bootstrap resolver, or the first system nameserver
/// when none is configured. Returns the ECHConfigList and the record TTL, or
/// `None` when no usable HTTPS record exists.
pub async fn query_ech_config(host: &str) -> io::Result<Option<(Vec<u8>, u32)>> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.parse::<IpAddr>().is_ok() {
        return Ok(None);
    }
    let resolver = match global() {
        Some(r) => r,
        None => {
            let Some(server) = system_nameserver().await else {
                return Ok(None);
            };
            BootstrapResolver {
                server,
                use_tcp: false,
            }
        }
    };
    let mut observation = LookupObservation::start(
        host,
        "HTTPS",
        LookupOrigin::Upstream(
            resolver.server,
            if resolver.use_tcp { "tcp" } else { "udp" },
        ),
    );
    let child = observation.as_ref().map(LookupObservation::child);
    let deadline = tokio::time::Instant::now() + QUERY_TIMEOUT;
    let operation = resolver.query_raw(host, QTYPE_HTTPS, deadline, observation.as_mut());
    let result = match child {
        Some(child) => child.scope(operation).await,
        None => operation.await,
    };
    if let Some(observation) = &mut observation {
        observation.finish(result.as_ref().map(|_| std::iter::empty()));
    }
    Ok(parse_https_rr_ech(&result?))
}

/// Where an observed lookup's answer comes from.
enum LookupOrigin {
    /// `/etc/hosts`, without a DNS exchange.
    Hosts,
    /// A bypass-marked exchange with this nameserver over this transport.
    Upstream(SocketAddr, &'static str),
}

struct LookupObservation {
    observer: crate::runtime::flow_observation::FlowObserver,
    data: crate::runtime::flow_observation::DnsLookup,
    finished: bool,
}

impl LookupObservation {
    fn start(host: &str, qtype: &str, origin: LookupOrigin) -> Option<Self> {
        use crate::runtime::flow_observation::{DnsLookup, FlowEvent, current};
        let observer = current()?;
        if host.is_empty() || host.len() > 253 {
            observer.publish(FlowEvent::Gap(
                crate::runtime::flow_observation::GapReason::Redacted,
            ));
            return None;
        }
        let context = observer.context();
        let (source, upstream) = match origin {
            LookupOrigin::Hosts => ("hosts", None),
            LookupOrigin::Upstream(address, transport) => ("upstream", Some((address, transport))),
        };
        let data = DnsLookup {
            lookup_id: uuid::Uuid::new_v4(),
            parent_lookup_id: context.lookup_id,
            attempt_id: context.attempt_id,
            purpose: context.dns_purpose,
            name: host.to_owned(),
            qtype: qtype.to_owned(),
            source,
            upstream_transport: upstream.map(|(_, transport)| transport),
            carrier_transport: upstream.map(|(_, transport)| transport),
            cache: "bypass",
            cache_entry_id: None,
            upstream: upstream.map(|(address, _)| address.to_string()),
            route_evaluation_ids: Vec::new(),
            status: "started",
            addresses: Vec::new(),
            selected_ip: None,
            error: None,
        };
        observer.publish(FlowEvent::Dns(data.clone()));
        Some(Self {
            observer,
            data,
            finished: false,
        })
    }

    fn child(&self) -> crate::runtime::flow_observation::FlowObserver {
        let mut context = self.observer.context();
        context.lookup_id = Some(self.data.lookup_id);
        self.observer.with_context(context)
    }

    fn finish<I: Iterator<Item = IpAddr>>(&mut self, result: Result<I, &io::Error>) {
        use crate::runtime::flow_observation::FlowEvent;
        self.finished = true;
        match result {
            Ok(addresses) => {
                self.data.status = "succeeded";
                for address in addresses {
                    if self.data.addresses.contains(&address) {
                        continue;
                    }
                    if self.data.addresses.len() == 32 {
                        self.observer.publish(FlowEvent::Gap(
                            crate::runtime::flow_observation::GapReason::BufferOverflow,
                        ));
                        break;
                    }
                    self.data.addresses.push(address);
                }
            }
            Err(error) => {
                self.data.status = "failed";
                self.data.error = Some(if error.kind() == io::ErrorKind::TimedOut {
                    "timeout"
                } else {
                    "resolution_failed"
                });
            }
        }
        self.observer.publish(FlowEvent::Dns(self.data.clone()));
    }
}

impl Drop for LookupObservation {
    fn drop(&mut self) {
        if !self.finished {
            self.data.status = "cancelled";
            self.data.error = Some("cancelled");
            self.observer
                .publish(crate::runtime::flow_observation::FlowEvent::Dns(
                    self.data.clone(),
                ));
        }
    }
}

#[cfg(test)]
pub(crate) fn run_global_test_in_child(name: &str) -> bool {
    const CHILD: &str = "HONK_GLOBAL_BOOTSTRAP_TEST_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return false;
    }
    // Ordinary resolver consumers do not take a test mutex around the global.
    let executable = std::env::current_exe().unwrap();
    let listed = std::process::Command::new(&executable)
        .args(["--exact", name, "--list", "--format", "terse"])
        .output()
        .unwrap();
    assert!(listed.status.success());
    assert_eq!(
        String::from_utf8(listed.stdout).unwrap().trim(),
        format!("{name}: test")
    );
    let status = std::process::Command::new(executable)
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name)
        .status()
        .unwrap();
    assert!(status.success());
    true
}

#[cfg(test)]
mod tests;
