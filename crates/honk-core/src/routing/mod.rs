//! Routing engine: compiles rules and determines outbound for connections.

use honk_config::routing::RoutingRule;
use regex::Regex;
use std::{net::IpAddr, sync::Arc};

mod geo;
mod lpm;

pub(crate) use geo::{GeoAssets, GeoRequirements, GeoSourceSet};
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
    pub name: String,
    /// Clash-style matched-rule type and payload (`clash_rule_parts`),
    /// e.g. ("GeoIP", "telegram") — the rule's own payload, not the
    /// connection's domain/IP.
    pub rule_type: String,
    pub rule_payload: String,
    pub priority: u32,
    pub domain_patterns: Vec<Regex>,
    pub domain_suffixes: Vec<String>,
    pub domain_keywords: Vec<String>,
    pub ip_nets: Vec<ipnet::IpNet>,
    /// Pre-built LPM trie for fast IP matching (derived from ip_nets).
    pub(crate) ip_trie: BinaryLpmTrie,
    pub source_ip_nets: Vec<ipnet::IpNet>,
    /// Pre-built LPM trie for fast source IP matching.
    pub(crate) source_ip_trie: BinaryLpmTrie,
    pub ports: Vec<PortRange>,
    pub source_ports: Vec<PortRange>,
    pub protocols: Vec<String>,
    pub process_names: Vec<String>,
    pub mac_addresses: Vec<String>,
    pub(crate) geosite_domains: Vec<GeositeDomain>,
    /// Pre-built hash/automaton matcher derived from `geosite_domains`.
    ///
    /// The naive representation costs O(domains) string operations (with
    /// per-candidate lowercase allocations) for every connection that falls
    /// back to userspace routing — with geosite:cn (~117k entries) that alone
    /// can saturate a core. This matcher reduces lookup to one lowercase pass
    /// plus hash/automaton probes.
    pub(crate) geosite_matcher: GeositeMatcher,
    pub ip_versions: Vec<u8>,
    pub dscp_values: Vec<u8>,
    /// Negated matchers (dae `!matcher(...)`): any hit vetoes the rule.
    /// Mirrors the positive fields above; `not_geo_ip` is expanded through
    /// GeoAssets into `not_ip_nets` exactly like the positive side.
    pub not_domain_patterns: Vec<Regex>,
    pub not_domain_suffixes: Vec<String>,
    pub not_domain_keywords: Vec<String>,
    pub not_ip_nets: Vec<ipnet::IpNet>,
    pub(crate) not_ip_trie: BinaryLpmTrie,
    pub not_source_ip_nets: Vec<ipnet::IpNet>,
    pub(crate) not_source_ip_trie: BinaryLpmTrie,
    pub not_ports: Vec<PortRange>,
    pub not_source_ports: Vec<PortRange>,
    pub not_protocols: Vec<String>,
    pub not_process_names: Vec<String>,
    pub not_mac_addresses: Vec<String>,
    pub(crate) not_geosite_domains: Vec<GeositeDomain>,
    pub(crate) not_geosite_matcher: GeositeMatcher,
    pub not_ip_versions: Vec<u8>,
    pub not_dscp_values: Vec<u8>,
    pub outbound: String,
    /// When true, matching this rule sets must=true on the result, which
    /// tells the control plane to skip TLS/HTTP sniffing.
    pub must: bool,
    pub mark: u32,
}

impl CompiledRoute {
    /// Whether the rule references any domain-class matcher (suffix, keyword,
    /// geosite, regex; negated or not).  While any such rule exists, a
    /// kernel routing decision made without the destination domain is not
    /// final — userspace SNI sniffing could re-route the flow — so the
    /// datapath's Rule-mode direct offload stays constrained.
    pub fn has_domain_conditions(&self) -> bool {
        !self.domain_suffixes.is_empty()
            || !self.domain_keywords.is_empty()
            || !self.geosite_domains.is_empty()
            || !self.domain_patterns.is_empty()
            || !self.not_domain_suffixes.is_empty()
            || !self.not_domain_keywords.is_empty()
            || !self.not_geosite_domains.is_empty()
            || !self.not_domain_patterns.is_empty()
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

#[derive(Debug, Clone, Copy)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
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
        let mut compiled = Vec::new();
        for rule in rules {
            let mut domain_patterns = Vec::new();
            for pattern in &rule.condition.domain_regex {
                domain_patterns.push(
                    Regex::new(pattern)
                        .map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", pattern, e))?,
                );
            }
            for wildcard in &rule.condition.domain {
                let regex_str = glob_to_regex(wildcard);
                domain_patterns.push(
                    Regex::new(&regex_str)
                        .map_err(|e| anyhow::anyhow!("Invalid pattern '{}': {}", wildcard, e))?,
                );
            }

            let mut ip_nets: Vec<ipnet::IpNet> = rule
                .condition
                .ip
                .iter()
                .filter_map(|c| parse_ip_net_str(c))
                .collect();
            ip_nets.extend(assets.geoip_nets(&rule.condition.geo_ip));

            let source_ip_nets: Vec<ipnet::IpNet> = rule
                .condition
                .source_ip
                .iter()
                .filter_map(|c| parse_ip_net_str(c))
                .collect();

            let ports = parse_port_ranges(&rule.condition.port)?;
            let source_ports = parse_port_ranges(&rule.condition.source_port)?;

            let mac_addresses: Vec<String> = rule
                .condition
                .mac
                .iter()
                .filter_map(|m| normalize_mac(m))
                .collect();

            let geosite_domains = assets.geosite_domains(&rule.condition.geosite);
            let geosite_matcher = GeositeMatcher::build(&geosite_domains);

            let ip_versions: Vec<u8> = rule
                .condition
                .ip_version
                .iter()
                .filter_map(|s| parse_ip_version(s))
                .collect();

            let dscp_values: Vec<u8> = rule
                .condition
                .dscp
                .iter()
                .filter_map(|s| s.trim().parse().ok())
                .collect();

            let ip_trie = BinaryLpmTrie::from_nets(&ip_nets);
            let source_ip_trie = BinaryLpmTrie::from_nets(&source_ip_nets);

            let not = &rule.condition.not;
            let mut not_domain_patterns = Vec::new();
            for pattern in &not.domain_regex {
                not_domain_patterns.push(
                    Regex::new(pattern)
                        .map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", pattern, e))?,
                );
            }
            for wildcard in &not.domain {
                let regex_str = glob_to_regex(wildcard);
                not_domain_patterns.push(
                    Regex::new(&regex_str)
                        .map_err(|e| anyhow::anyhow!("Invalid pattern '{}': {}", wildcard, e))?,
                );
            }
            let mut not_ip_nets: Vec<ipnet::IpNet> =
                not.ip.iter().filter_map(|c| parse_ip_net_str(c)).collect();
            not_ip_nets.extend(assets.geoip_nets(&not.geo_ip));
            let not_source_ip_nets: Vec<ipnet::IpNet> = not
                .source_ip
                .iter()
                .filter_map(|c| parse_ip_net_str(c))
                .collect();
            let not_ports = parse_port_ranges(&not.port)?;
            let not_source_ports = parse_port_ranges(&not.source_port)?;
            let not_mac_addresses: Vec<String> =
                not.mac.iter().filter_map(|m| normalize_mac(m)).collect();
            let not_geosite_domains = assets.geosite_domains(&not.geosite);
            let not_geosite_matcher = GeositeMatcher::build(&not_geosite_domains);
            let not_ip_versions: Vec<u8> = not
                .ip_version
                .iter()
                .filter_map(|s| parse_ip_version(s))
                .collect();
            let not_dscp_values: Vec<u8> = not
                .dscp
                .iter()
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            let not_ip_trie = BinaryLpmTrie::from_nets(&not_ip_nets);
            let not_source_ip_trie = BinaryLpmTrie::from_nets(&not_source_ip_nets);

            let (outbound, outbound_must) = parse_outbound(rule.outbound.as_str());

            let (rule_type, rule_payload) = rule
                .condition
                .clash_rule_parts()
                .map(|(t, p)| (t.to_string(), p))
                .unwrap_or_else(|| ("Match".to_string(), String::new()));

            compiled.push(CompiledRoute {
                name: rule.name.clone(),
                rule_type,
                rule_payload,
                priority: rule.priority,
                domain_patterns,
                domain_suffixes: rule.condition.domain_suffix.clone(),
                domain_keywords: rule.condition.domain_keyword.clone(),
                ip_nets,
                ip_trie,
                source_ip_nets,
                source_ip_trie,
                ports,
                source_ports,
                protocols: rule.condition.protocol.clone(),
                process_names: rule
                    .condition
                    .process_name
                    .iter()
                    .map(|name| normalize_process_matcher(name))
                    .collect(),
                mac_addresses,
                geosite_domains,
                geosite_matcher,
                ip_versions,
                dscp_values,
                not_domain_patterns,
                not_domain_suffixes: not.domain_suffix.clone(),
                not_domain_keywords: not.domain_keyword.clone(),
                not_ip_nets,
                not_ip_trie,
                not_source_ip_nets,
                not_source_ip_trie,
                not_ports,
                not_source_ports,
                not_protocols: not.protocol.clone(),
                not_process_names: not
                    .process_name
                    .iter()
                    .map(|name| normalize_process_matcher(name))
                    .collect(),

                not_mac_addresses,
                not_geosite_domains,
                not_geosite_matcher,
                not_ip_versions,
                not_dscp_values,
                outbound,
                must: rule.must || outbound_must,
                mark: rule.mark,
            });
        }

        compiled.sort_by_key(|r| r.priority);

        let (default_outbound, _default_must) = parse_outbound(default_outbound);

        Ok(Self {
            routes: CompiledRoutes::new(compiled, geo_fingerprint, requirements),
            default_outbound: default_outbound.into(),
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

    pub fn route(&self, conn: &ConnectionInfo) -> &str {
        match self.route_full(conn) {
            Some(r) => r.outbound_name,
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

    /// Route and report whether the decision came from a `(must)` rule.
    /// The default-outbound fallback never carries `must`.
    pub fn route_with_must(&self, conn: &ConnectionInfo) -> (&str, bool) {
        match self.route_full(conn) {
            Some(r) => (r.outbound_name, r.must),
            None => (self.default_outbound(), false),
        }
    }

    /// Route with full metadata. Returns `None` if no rule matched (caller
    /// should use default outbound). A `(must)` rule is terminal and tells
    /// the control plane to skip TLS/HTTP sniffing.
    pub fn route_full<'a>(&'a self, conn: &ConnectionInfo) -> Option<RouteMatch<'a>> {
        for route in self.routes.iter() {
            if self.match_route(route, conn) {
                tracing::debug!(
                    "Connection {} matched rule '{}' → '{}' (must={}, mark={})",
                    conn_log_id(conn),
                    route.name,
                    route.outbound,
                    route.must,
                    route.mark
                );
                return Some(RouteMatch {
                    outbound_name: &route.outbound,
                    rule_name: &route.name,
                    rule_type: &route.rule_type,
                    rule_payload: &route.rule_payload,
                    must: route.must,
                    mark: route.mark,
                });
            }
        }

        None
    }

    /// Domain-only lookup used by DNS snooping / DOMAIN_ROUTING_MAP updates.
    ///
    /// Only rules that carry a domain / geosite condition are considered.
    /// Pure IP/port/process/mac rules are skipped so an unspecified
    /// `0.0.0.0:0` probe cannot spuriously match `dip(geoip:…)` or
    /// `dport(…)` and produce a misleading "Connection 0.0.0.0:0 → …" log.
    ///
    /// Returns `None` when no domain rule matches — the real connection will
    /// re-evaluate with a full 5-tuple (and must not receive a DOMAIN_ROUTING
    /// fast-path entry for this domain).
    pub fn route_domain<'a>(&'a self, domain: &str) -> Option<RouteMatch<'a>> {
        let conn = ConnectionInfo {
            domain: Some(domain.to_string()),
            // Unspecified 5-tuple: domain/geosite conditions still match;
            // IP/port/process conditions fail closed (see match_route).
            dst_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            dst_port: 0,
            src_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            // Domain rules rarely pin l4proto; "tcp" is the common case and
            // does not affect pure domain/geosite matches.
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        };

        for route in self.routes.iter() {
            if !route_has_domain_condition(route) {
                continue;
            }
            if self.match_route(route, &conn) {
                tracing::debug!(
                    "Domain '{}' matched rule '{}' → '{}' (must={}, mark={})",
                    domain,
                    route.name,
                    route.outbound,
                    route.must,
                    route.mark
                );
                return Some(RouteMatch {
                    outbound_name: &route.outbound,
                    rule_name: &route.name,
                    rule_type: &route.rule_type,
                    rule_payload: &route.rule_payload,
                    must: route.must,
                    mark: route.mark,
                });
            }
        }

        tracing::trace!(
            "Domain '{}' matched no domain rule (defer to connection-time routing; default would be '{}')",
            domain,
            self.default_outbound
        );
        None
    }

    /// Check if a connection matches a compiled route (all groups AND, within-group OR).
    fn match_route(&self, route: &CompiledRoute, conn: &ConnectionInfo) -> bool {
        let has_conditions = !route.domain_patterns.is_empty()
            || !route.domain_suffixes.is_empty()
            || !route.domain_keywords.is_empty()
            || !route.ip_nets.is_empty()
            || !route.source_ip_nets.is_empty()
            || !route.ports.is_empty()
            || !route.source_ports.is_empty()
            || !route.protocols.is_empty()
            || !route.process_names.is_empty()
            || !route.mac_addresses.is_empty()
            || !route.geosite_domains.is_empty()
            || !route.ip_versions.is_empty()
            || !route.dscp_values.is_empty()
            || Self::has_negated_conditions(route);
        if !has_conditions {
            return false;
        }

        if !route.domain_patterns.is_empty()
            || !route.domain_suffixes.is_empty()
            || !route.domain_keywords.is_empty()
        {
            match conn.domain {
                Some(ref domain) => {
                    let dm = route.domain_patterns.iter().any(|re| re.is_match(domain))
                        || route.domain_suffixes.iter().any(|s| domain.ends_with(s))
                        || route.domain_keywords.iter().any(|k| domain.contains(k));
                    if !dm {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // IP matching (uses pre-built LPM trie for O(key_bits) lookup)
        if !route.ip_nets.is_empty() && !route.ip_trie.matches(&conn.dst_ip) {
            return false;
        }

        // Source IP matching (uses pre-built LPM trie)
        if !route.source_ip_nets.is_empty() && !route.source_ip_trie.matches(&conn.src_ip) {
            return false;
        }

        if !route.ports.is_empty() && !route.ports.iter().any(|r| r.contains(conn.dst_port)) {
            return false;
        }

        if !route.source_ports.is_empty()
            && !route.source_ports.iter().any(|r| r.contains(conn.src_port))
        {
            return false;
        }

        if !route.protocols.is_empty()
            && !route
                .protocols
                .iter()
                .any(|p| p.eq_ignore_ascii_case(conn.protocol))
        {
            return false;
        }

        if !route.process_names.is_empty() {
            match conn.process_name {
                Some(ref proc) => {
                    if !route.process_names.iter().any(|p| proc.contains(p)) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        if !route.mac_addresses.is_empty() {
            match conn.mac {
                Some(ref mac) => match normalize_mac(mac) {
                    Some(ref canonical) if route.mac_addresses.contains(canonical) => {}
                    _ => return false,
                },
                None => return false,
            }
        }

        if !route.geosite_domains.is_empty() {
            match conn.domain {
                Some(ref domain) => {
                    if !route.geosite_matcher.matches(domain) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        if !route.ip_versions.is_empty() {
            let version = if conn.dst_ip.is_ipv4() { 4 } else { 6 };
            if !route.ip_versions.contains(&version) {
                return false;
            }
        }

        if !route.dscp_values.is_empty() {
            match conn.dscp {
                Some(dscp) => {
                    if !route.dscp_values.contains(&dscp) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        !Self::negated_hit(route, conn)
    }

    fn has_negated_conditions(route: &CompiledRoute) -> bool {
        !route.not_domain_patterns.is_empty()
            || !route.not_domain_suffixes.is_empty()
            || !route.not_domain_keywords.is_empty()
            || !route.not_ip_nets.is_empty()
            || !route.not_source_ip_nets.is_empty()
            || !route.not_ports.is_empty()
            || !route.not_source_ports.is_empty()
            || !route.not_protocols.is_empty()
            || !route.not_process_names.is_empty()
            || !route.not_mac_addresses.is_empty()
            || !route.not_geosite_domains.is_empty()
            || !route.not_ip_versions.is_empty()
            || !route.not_dscp_values.is_empty()
    }

    /// True when any negated matcher hits and therefore vetoes the rule.
    /// An absent domain cannot prove a negated domain/geosite matcher, so it
    /// never vetoes — "cannot prove it is x" counts as "is not x" (dae).
    fn negated_hit(route: &CompiledRoute, conn: &ConnectionInfo) -> bool {
        if let Some(ref domain) = conn.domain
            && (route
                .not_domain_patterns
                .iter()
                .any(|re| re.is_match(domain))
                || route
                    .not_domain_suffixes
                    .iter()
                    .any(|s| domain.ends_with(s))
                || route.not_domain_keywords.iter().any(|k| domain.contains(k))
                || route.not_geosite_matcher.matches(domain))
        {
            return true;
        }
        if !route.not_ip_nets.is_empty() && route.not_ip_trie.matches(&conn.dst_ip) {
            return true;
        }
        if !route.not_source_ip_nets.is_empty() && route.not_source_ip_trie.matches(&conn.src_ip) {
            return true;
        }
        if route.not_ports.iter().any(|r| r.contains(conn.dst_port)) {
            return true;
        }
        if route
            .not_source_ports
            .iter()
            .any(|r| r.contains(conn.src_port))
        {
            return true;
        }
        if route
            .not_protocols
            .iter()
            .any(|p| p.eq_ignore_ascii_case(conn.protocol))
        {
            return true;
        }
        if let Some(ref proc) = conn.process_name
            && route.not_process_names.iter().any(|p| proc.contains(p))
        {
            return true;
        }
        if let Some(ref mac) = conn.mac
            && let Some(canonical) = normalize_mac(mac)
            && route.not_mac_addresses.contains(&canonical)
        {
            return true;
        }
        if !route.not_ip_versions.is_empty() {
            let version = if conn.dst_ip.is_ipv4() { 4 } else { 6 };
            if route.not_ip_versions.contains(&version) {
                return true;
            }
        }
        if let Some(dscp) = conn.dscp
            && route.not_dscp_values.contains(&dscp)
        {
            return true;
        }
        false
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
    pub outbound_name: &'a str,
    pub rule_name: &'a str,
    /// Clash-style matched-rule type and payload.
    pub rule_type: &'a str,
    pub rule_payload: &'a str,
    pub must: bool,
    pub mark: u32,
}

/// True when the compiled rule can match on domain identity alone
/// (suffix / keyword / regex / geosite). Used by [`Router::route_domain`].
fn route_has_domain_condition(route: &CompiledRoute) -> bool {
    !route.domain_patterns.is_empty()
        || !route.domain_suffixes.is_empty()
        || !route.domain_keywords.is_empty()
        || !route.geosite_domains.is_empty()
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
