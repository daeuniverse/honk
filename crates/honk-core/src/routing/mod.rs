//! Routing engine: compiles rules and determines outbound for connections.

use honk_config::routing::RoutingRule;
use honk_ebpf_common::{DomainRouting, ROUTING_FACT_CAPACITY};
use regex::Regex;
use std::{net::IpAddr, sync::Arc};

mod fingerprint;
mod geo;
mod ir;
mod lpm;

pub(crate) use geo::{GeoAssets, GeoRequirements, GeoSourceSet};
pub use ir::{CompiledCondition, CompiledPredicate, IpMatcher, PortRange};
pub(crate) use lpm::BinaryLpmTrie;

// Read-only dat scan API consumed by honk-tool (`geosite`/`geoip`
// subcommands); separate from the routing hot path.
pub use geo::{
    GeoipCategory, GeoipScan, GeositeCategory, GeositeEntry, GeositeKind, GeositeScan,
    find_geoip_dat, find_geosite_dat,
};
const KERNEL_COMM_VISIBLE_LEN: usize = honk_ebpf_common::TASK_COMM_LEN - 1;

fn normalize_process_matcher(name: &str) -> String {
    let bytes = name.as_bytes();
    let len = bytes.len().min(KERNEL_COMM_VISIBLE_LEN);
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[derive(Debug, Clone)]
pub struct CompiledRoute {
    pub id: u32,
    pub name: String,
    /// Clash-style matched-rule type and payload (`clash_rule_parts`).
    pub rule_type: String,
    pub rule_payload: String,
    pub priority: u32,
    pub conditions: Vec<CompiledCondition>,
    pub outbound: String,
    /// A matching configured must rule is terminal.
    pub must: bool,
    pub mark: u32,
}

impl CompiledRoute {
    /// Whether the rule references any domain-class matcher, positive or negated.
    pub fn has_domain_conditions(&self) -> bool {
        self.conditions
            .iter()
            .any(|condition| matches!(condition.predicate, CompiledPredicate::Domain(_)))
    }
}

#[derive(Debug, Clone)]
pub(crate) enum GeositeDomain {
    Full(String),
    Domain(String),
    Keyword(String),
    Regex(Regex),
}

/// Fast matcher over a compiled geosite domain list.
///
/// Lookup semantics mirror the historical per-entry `match_geosite_domain`:
/// `Full` is a case-insensitive exact match, `Domain` matches the host itself
/// or any dot-boundary sub-domain (case-insensitive), `Keyword` is a
/// case-sensitive substring match, and `Regex` runs against the original
/// (non-lowercased) domain.
#[derive(Debug, Clone, Default)]
pub(crate) struct GeositeMatcher {
    /// Exact host names, stored lowercased.
    full: std::collections::HashSet<String>,
    /// Dot-boundary suffixes, stored lowercased.
    suffix: std::collections::HashSet<String>,
    /// Case-sensitive substring automaton for keywords.
    keyword_ac: Option<aho_corasick::AhoCorasick>,
    /// Full regular expressions (matched against the original domain).
    regex: Vec<Regex>,
}

impl GeositeMatcher {
    pub(crate) fn build(domains: &[GeositeDomain]) -> Self {
        let mut matcher = GeositeMatcher::default();
        let mut keywords: Vec<&str> = Vec::new();
        for d in domains {
            match d {
                GeositeDomain::Full(v) => {
                    matcher.full.insert(v.to_lowercase());
                }
                GeositeDomain::Domain(v) => {
                    matcher.suffix.insert(v.to_lowercase());
                }
                GeositeDomain::Keyword(v) => keywords.push(v.as_str()),
                GeositeDomain::Regex(re) => matcher.regex.push(re.clone()),
            }
        }
        if !keywords.is_empty() {
            matcher.keyword_ac = aho_corasick::AhoCorasick::new(&keywords).ok();
        }
        matcher
    }

    pub(crate) fn matches(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        if self.full.contains(lower.as_str()) {
            return true;
        }
        // Dot-boundary suffix walk: check the host itself, then each parent.
        if !self.suffix.is_empty() {
            let mut d = lower.as_str();
            loop {
                if self.suffix.contains(d) {
                    return true;
                }
                match d.find('.') {
                    Some(i) => d = &d[i + 1..],
                    None => break,
                }
            }
        }
        if let Some(ac) = &self.keyword_ac
            && ac.is_match(domain)
        {
            return true;
        }
        self.regex.iter().any(|re| re.is_match(domain))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DomainMatcherKey {
    class: u8,
    alternatives: Vec<(u8, String)>,
}

#[derive(Debug, Clone)]
enum DomainMatcher {
    Ordinary {
        key: DomainMatcherKey,
        patterns: Vec<Regex>,
        suffixes: Vec<String>,
        keywords: Vec<String>,
    },
    Geosite {
        key: DomainMatcherKey,
        matcher: GeositeMatcher,
    },
}

impl DomainMatcher {
    fn ordinary(
        domains: &[String],
        suffixes: &[String],
        keywords: &[String],
        regexes: &[String],
    ) -> anyhow::Result<Self> {
        let mut patterns = Vec::with_capacity(regexes.len() + domains.len());
        for pattern in regexes {
            patterns.push(
                Regex::new(pattern)
                    .map_err(|error| anyhow::anyhow!("Invalid regex '{}': {}", pattern, error))?,
            );
        }
        for wildcard in domains {
            patterns.push(
                Regex::new(&glob_to_regex(wildcard)).map_err(|error| {
                    anyhow::anyhow!("Invalid pattern '{}': {}", wildcard, error)
                })?,
            );
        }
        let mut alternatives = patterns
            .iter()
            .map(|pattern| (0, pattern.as_str().to_owned()))
            .chain(suffixes.iter().cloned().map(|value| (1, value)))
            .chain(keywords.iter().cloned().map(|value| (2, value)))
            .collect::<Vec<_>>();
        alternatives.sort();
        alternatives.dedup();
        Ok(Self::Ordinary {
            key: DomainMatcherKey {
                class: 0,
                alternatives,
            },
            patterns,
            suffixes: suffixes.to_vec(),
            keywords: keywords.to_vec(),
        })
    }

    fn geosite(domains: Vec<GeositeDomain>) -> Self {
        let mut alternatives = domains
            .iter()
            .map(|domain| match domain {
                GeositeDomain::Full(value) => (0, value.to_lowercase()),
                GeositeDomain::Domain(value) => (1, value.to_lowercase()),
                GeositeDomain::Keyword(value) => (2, value.clone()),
                GeositeDomain::Regex(value) => (3, value.as_str().to_owned()),
            })
            .collect::<Vec<_>>();
        alternatives.sort();
        alternatives.dedup();
        Self::Geosite {
            key: DomainMatcherKey {
                class: 1,
                alternatives,
            },
            matcher: GeositeMatcher::build(&domains),
        }
    }

    fn key(&self) -> &DomainMatcherKey {
        match self {
            Self::Ordinary { key, .. } | Self::Geosite { key, .. } => key,
        }
    }

    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Ordinary {
                patterns,
                suffixes,
                keywords,
                ..
            } => {
                patterns.iter().any(|pattern| pattern.is_match(domain))
                    || suffixes.iter().any(|suffix| domain.ends_with(suffix))
                    || keywords.iter().any(|keyword| domain.contains(keyword))
            }
            Self::Geosite { matcher, .. } => matcher.matches(domain),
        }
    }
}

#[derive(Debug, Default)]
struct DomainRegistry(Vec<DomainMatcher>);

impl DomainRegistry {
    fn intern(&mut self, matcher: DomainMatcher) -> anyhow::Result<u32> {
        if let Some(id) = self
            .0
            .iter()
            .position(|candidate| candidate.key() == matcher.key())
        {
            return Ok(id as u32);
        }
        anyhow::ensure!(
            self.0.len() < ROUTING_FACT_CAPACITY,
            "routing policy has more than {ROUTING_FACT_CAPACITY} domain predicates"
        );
        let id = self.0.len() as u32;
        self.0.push(matcher);
        Ok(id)
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub domain: Option<String>,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub protocol: &'static str,
    pub process_name: Option<String>,
    pub mac: Option<String>,
    pub dscp: Option<u8>,
}

/// Human-readable connection identity for routing debug logs.
///
/// Domain-only probes (DNS snoop) used to log as `0.0.0.0:0`, which looked
/// like a broken TPROXY original-destination. Prefer the domain name when
/// the 5-tuple is unspecified.
fn conn_log_id(conn: &ConnectionInfo) -> String {
    match &conn.domain {
        Some(d) if conn.dst_ip.is_unspecified() && conn.dst_port == 0 => {
            format!("domain '{d}'")
        }
        Some(d) => format!("{}:{} (domain '{d}')", conn.dst_ip, conn.dst_port),
        None => format!("{}:{}", conn.dst_ip, conn.dst_port),
    }
}

#[derive(Debug, Clone)]
struct CompiledRoutes {
    routes: Arc<[CompiledRoute]>,
    geo_fingerprint: [u8; 32],
    geo_requirements: GeoRequirements,
}

impl CompiledRoutes {
    fn new(
        routes: Vec<CompiledRoute>,
        geo_fingerprint: [u8; 32],
        geo_requirements: GeoRequirements,
    ) -> Self {
        Self {
            routes: routes.into(),
            geo_fingerprint,
            geo_requirements,
        }
    }
}

impl From<Vec<CompiledRoute>> for CompiledRoutes {
    fn from(routes: Vec<CompiledRoute>) -> Self {
        let requirements = GeoRequirements::default();
        let sources = GeoSourceSet::load(&requirements);
        Self::new(routes, sources.fingerprint(), requirements)
    }
}

impl std::ops::Deref for CompiledRoutes {
    type Target = Arc<[CompiledRoute]>;

    fn deref(&self) -> &Self::Target {
        &self.routes
    }
}

impl AsRef<[CompiledRoute]> for CompiledRoutes {
    fn as_ref(&self) -> &[CompiledRoute] {
        &self.routes
    }
}

#[derive(Debug, Clone)]
pub struct Router {
    routes: CompiledRoutes,
    default_outbound: Arc<str>,
    domain_matchers: Arc<[DomainMatcher]>,
    policy_fingerprint: [u8; 32],
}

impl Router {
    pub fn new(rules: &[RoutingRule], default_outbound: &str) -> anyhow::Result<Self> {
        let requirements = GeoRequirements::for_traffic(rules);
        let sources = GeoSourceSet::load(&requirements);
        Self::new_with_geo_sources(rules, default_outbound, &sources)
    }

    pub(crate) fn new_with_geo_sources(
        rules: &[RoutingRule],
        default_outbound: &str,
        geo_sources: &GeoSourceSet,
    ) -> anyhow::Result<Self> {
        let requirements = GeoRequirements::for_traffic(rules);
        let assets = GeoAssets::from_sources(&requirements, geo_sources);
        let geo_fingerprint = geo_sources.fingerprint_for(&requirements);
        let mut registry = DomainRegistry::default();
        let mut compiled = Vec::with_capacity(rules.len());

        for (source_index, rule) in rules.iter().enumerate() {
            let mut conditions = Vec::new();
            append_conditions(&mut conditions, false, rule, &assets, &mut registry)?;
            append_conditions(&mut conditions, true, rule, &assets, &mut registry)?;

            let (outbound, outbound_must) = parse_outbound(rule.outbound.as_str());
            let (rule_type, rule_payload) = rule
                .condition
                .clash_rule_parts()
                .map(|(kind, payload)| (kind.to_owned(), payload))
                .unwrap_or_else(|| ("Match".to_owned(), String::new()));
            compiled.push(CompiledRoute {
                id: source_index as u32,
                name: rule.name.clone(),
                rule_type,
                rule_payload,
                priority: rule.priority,
                conditions,
                outbound,
                must: rule.must || outbound_must,
                mark: rule.mark,
            });
        }

        // `sort_by_key` is stable, so equal priorities retain source order.
        compiled.sort_by_key(|route| route.priority);
        for (id, route) in compiled.iter_mut().enumerate() {
            route.id = id as u32;
        }

        let (default_outbound, _default_must) = parse_outbound(default_outbound);
        let policy_fingerprint =
            fingerprint::policy(&compiled, &registry.0, &default_outbound, geo_fingerprint);
        Ok(Self {
            routes: CompiledRoutes::new(compiled, geo_fingerprint, requirements),
            default_outbound: default_outbound.into(),
            domain_matchers: registry.0.into(),
            policy_fingerprint,
        })
    }

    pub fn default_outbound(&self) -> &str {
        self.default_outbound.as_ref()
    }

    pub(crate) fn geo_fingerprint(&self) -> [u8; 32] {
        self.routes.geo_fingerprint
    }

    pub(crate) fn geo_requirements(&self) -> &GeoRequirements {
        &self.routes.geo_requirements
    }

    pub fn policy_fingerprint(&self) -> [u8; 32] {
        self.policy_fingerprint
    }

    pub fn domain_predicate_count(&self) -> usize {
        self.domain_matchers.len()
    }

    pub fn domain_bitmap(&self, domain: &str) -> Option<DomainRouting> {
        if self.domain_matchers.is_empty() {
            return None;
        }
        let mut bitmap = DomainRouting::default();
        for (id, matcher) in self.domain_matchers.iter().enumerate() {
            if matcher.matches(domain) {
                bitmap.bitmap[id / 32] |= 1 << (id % 32);
            }
        }
        Some(bitmap)
    }

    pub fn route(&self, conn: &ConnectionInfo) -> &str {
        match self.route_full(conn) {
            Some(result) => result.outbound_name,
            None => {
                tracing::debug!(
                    "Connection {} → default outbound '{}'",
                    conn_log_id(conn),
                    self.default_outbound
                );
                self.default_outbound.as_ref()
            }
        }
    }

    pub fn route_with_must(&self, conn: &ConnectionInfo) -> (&str, bool) {
        match self.route_full(conn) {
            Some(result) => (result.outbound_name, result.must),
            None => (self.default_outbound(), false),
        }
    }

    pub fn route_full<'a>(&'a self, conn: &ConnectionInfo) -> Option<RouteMatch<'a>> {
        self.route_full_with_domain_bitmap(conn, None)
    }

    pub fn route_full_with_domain_bitmap<'a>(
        &'a self,
        conn: &ConnectionInfo,
        domain_bitmap: Option<&DomainRouting>,
    ) -> Option<RouteMatch<'a>> {
        self.routes.iter().find_map(|route| {
            if !self.matches_route(route, conn, domain_bitmap) {
                return None;
            }
            tracing::debug!(
                "Connection {} matched rule '{}' → '{}' (must={}, mark={})",
                conn_log_id(conn),
                route.name,
                route.outbound,
                route.must,
                route.mark
            );
            Some(RouteMatch {
                rule_id: route.id,
                outbound_name: &route.outbound,
                rule_name: &route.name,
                rule_type: &route.rule_type,
                rule_payload: &route.rule_payload,
                must: route.must,
                mark: route.mark,
            })
        })
    }

    fn matches_route(
        &self,
        route: &CompiledRoute,
        conn: &ConnectionInfo,
        domain_bitmap: Option<&DomainRouting>,
    ) -> bool {
        !route.conditions.is_empty()
            && route.conditions.iter().all(|condition| {
                let matched = self.matches_predicate(&condition.predicate, conn, domain_bitmap);
                if condition.not { !matched } else { matched }
            })
    }

    fn matches_predicate(
        &self,
        predicate: &CompiledPredicate,
        conn: &ConnectionInfo,
        domain_bitmap: Option<&DomainRouting>,
    ) -> bool {
        match predicate {
            CompiledPredicate::Domain(id) => domain_bitmap
                .map(|bitmap| {
                    let id = *id as usize;
                    id < ROUTING_FACT_CAPACITY && bitmap.bitmap[id / 32] & (1 << (id % 32)) != 0
                })
                .or_else(|| {
                    conn.domain.as_deref().map(|domain| {
                        self.domain_matchers
                            .get(*id as usize)
                            .is_some_and(|matcher| matcher.matches(domain))
                    })
                })
                .unwrap_or(false),
            CompiledPredicate::DestinationIp(matcher) => matcher.matches(&conn.dst_ip),
            CompiledPredicate::SourceIp(matcher) => matcher.matches(&conn.src_ip),
            CompiledPredicate::DestinationPort(ranges) => {
                ranges.iter().any(|range| range.contains(conn.dst_port))
            }
            CompiledPredicate::SourcePort(ranges) => {
                ranges.iter().any(|range| range.contains(conn.src_port))
            }
            CompiledPredicate::Protocol(mask) => protocol_value(conn.protocol) & *mask != 0,
            CompiledPredicate::IpVersion(mask) => {
                let version = if conn.dst_ip.is_ipv4() { 1 } else { 2 };
                *mask & version != 0
            }
            CompiledPredicate::Dscp(values) => conn.dscp.is_some_and(|dscp| values.contains(&dscp)),
            CompiledPredicate::ProcessName(patterns) => conn
                .process_name
                .as_deref()
                .is_some_and(|name| patterns.iter().any(|pattern| name.contains(pattern))),
            CompiledPredicate::Mac(macs) => conn
                .mac
                .as_deref()
                .and_then(normalize_mac_bytes)
                .is_some_and(|mac| macs.contains(&mac)),
        }
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    pub fn compiled_routes(&self) -> &[CompiledRoute] {
        self.routes.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct RouteMatch<'a> {
    pub rule_id: u32,
    pub outbound_name: &'a str,
    pub rule_name: &'a str,
    pub rule_type: &'a str,
    pub rule_payload: &'a str,
    pub must: bool,
    pub mark: u32,
}

fn append_conditions(
    conditions: &mut Vec<CompiledCondition>,
    not: bool,
    rule: &RoutingRule,
    assets: &GeoAssets,
    registry: &mut DomainRegistry,
) -> anyhow::Result<()> {
    macro_rules! field {
        ($name:ident) => {
            if not {
                &rule.condition.not.$name
            } else {
                &rule.condition.$name
            }
        };
    }
    let domains = field!(domain);
    let domain_suffixes = field!(domain_suffix);
    let domain_keywords = field!(domain_keyword);
    let domain_regex = field!(domain_regex);
    let ips = field!(ip);
    let source_ips = field!(source_ip);
    let ports = field!(port);
    let source_ports = field!(source_port);
    let protocols = field!(protocol);
    let process_names = field!(process_name);
    let macs = field!(mac);
    let geo_ips = field!(geo_ip);
    let geosites = field!(geosite);
    let ip_versions = field!(ip_version);
    let dscps = field!(dscp);
    if !domains.is_empty()
        || !domain_suffixes.is_empty()
        || !domain_keywords.is_empty()
        || !domain_regex.is_empty()
    {
        let id = registry.intern(DomainMatcher::ordinary(
            domains,
            domain_suffixes,
            domain_keywords,
            domain_regex,
        )?)?;
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::Domain(id),
        });
    }
    if !geosites.is_empty() {
        let id = registry.intern(DomainMatcher::geosite(assets.geosite_domains(geosites)))?;
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::Domain(id),
        });
    }
    if !ips.is_empty() || !geo_ips.is_empty() {
        let mut nets: Vec<_> = ips
            .iter()
            .filter_map(|value| parse_ip_net_str(value))
            .collect();
        nets.extend(assets.geoip_nets(geo_ips));
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::DestinationIp(Arc::new(IpMatcher::new(nets))),
        });
    }
    if !source_ips.is_empty() {
        let nets = source_ips
            .iter()
            .filter_map(|value| parse_ip_net_str(value))
            .collect();
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::SourceIp(Arc::new(IpMatcher::new(nets))),
        });
    }
    if !ports.is_empty() {
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::DestinationPort(parse_port_ranges(ports)?),
        });
    }
    if !source_ports.is_empty() {
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::SourcePort(parse_port_ranges(source_ports)?),
        });
    }
    if !protocols.is_empty() {
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::Protocol(protocol_mask(protocols)),
        });
    }
    if !process_names.is_empty() {
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::ProcessName(
                process_names
                    .iter()
                    .map(|name| normalize_process_matcher(name))
                    .collect(),
            ),
        });
    }
    if !macs.is_empty() {
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::Mac(
                macs.iter()
                    .filter_map(|mac| normalize_mac_bytes(mac))
                    .collect(),
            ),
        });
    }
    if !ip_versions.is_empty() {
        let mask = ip_versions
            .iter()
            .filter_map(|value| parse_ip_version(value))
            .fold(0, |mask, version| mask | if version == 4 { 1 } else { 2 });
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::IpVersion(mask),
        });
    }
    if !dscps.is_empty() {
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::Dscp(
                dscps
                    .iter()
                    .filter_map(|value| value.trim().parse().ok())
                    .collect(),
            ),
        });
    }
    Ok(())
}

fn protocol_mask(protocols: &[String]) -> u8 {
    protocols.iter().fold(0, |mask, protocol| {
        mask | if protocol.eq_ignore_ascii_case("tcp") {
            1
        } else if protocol.eq_ignore_ascii_case("udp") {
            2
        } else {
            0
        }
    })
}

fn protocol_value(protocol: &str) -> u8 {
    if protocol.eq_ignore_ascii_case("tcp") {
        1
    } else if protocol.eq_ignore_ascii_case("udp") {
        2
    } else {
        0
    }
}

/// Normalize MAC to canonical `aa:bb:cc:dd:ee:ff` form.
/// Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`, `aabbccddeeff`.
fn normalize_mac(s: &str) -> Option<String> {
    let stripped: String = s
        .chars()
        .filter(|&c| c != ':' && c != '-' && c != '.')
        .collect();
    if stripped.len() != 12 {
        return None;
    }
    let bytes: Vec<u8> = (0..12)
        .step_by(2)
        .map(|i| u8::from_str_radix(&stripped[i..i + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    Some(
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn normalize_mac_bytes(s: &str) -> Option<[u8; 6]> {
    let canonical = normalize_mac(s)?;
    let mut bytes = [0_u8; 6];
    for (index, value) in canonical.split(':').enumerate() {
        bytes[index] = u8::from_str_radix(value, 16).ok()?;
    }
    Some(bytes)
}

/// Strip `(must)` suffix from outbound name, returning (name, must_flag).
fn parse_outbound(outbound: &str) -> (String, bool) {
    if let Some(stripped) = outbound.strip_suffix("(must)") {
        (stripped.to_string(), true)
    } else {
        (outbound.to_string(), false)
    }
}

fn parse_ip_version(s: &str) -> Option<u8> {
    match s.trim().to_lowercase().as_str() {
        "4" | "ipv4" => Some(4),
        "6" | "ipv6" => Some(6),
        _ => None,
    }
}

/// Parse a dae `dip`/`sip` argument into an `IpNet`. `ipnet`'s `FromStr`
/// rejects bare addresses, but dae configs write them freely — a bare IP is
/// a host route (/32 or /128). Silently dropping it would silently drop the
/// whole matcher.
pub(crate) fn parse_ip_net_str(s: &str) -> Option<ipnet::IpNet> {
    let trimmed = s.trim();
    if trimmed.contains('/') {
        return trimmed.parse().ok();
    }
    if trimmed.contains(':') {
        return format!("{trimmed}/128").parse().ok();
    }
    format!("{trimmed}/32").parse().ok()
}

fn parse_port_ranges(ports: &[String]) -> anyhow::Result<Vec<PortRange>> {
    let mut ranges = Vec::new();
    for port_str in ports {
        if let Some((start, end)) = port_str.split_once('-') {
            let start: u16 = start
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid port: {}", port_str))?;
            let end: u16 = end
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid port: {}", port_str))?;
            ranges.push(PortRange { start, end });
        } else {
            let port: u16 = port_str
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid port: {}", port_str))?;
            ranges.push(PortRange {
                start: port,
                end: port,
            });
        }
    }
    Ok(ranges)
}
fn glob_to_regex(pattern: &str) -> String {
    let mut re = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\' => {
                re.push('\\');
                re.push(ch);
            }
            c => re.push(c),
        }
    }
    re.push('$');
    re
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod golden;
