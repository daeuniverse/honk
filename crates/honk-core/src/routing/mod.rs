//! Routing engine: compiles rules and determines outbound for connections.

use honk_config::routing::{RoutingConfig, RoutingRule};
use honk_ebpf_common::{DomainRouting, ROUTING_FACT_CAPACITY};
use honk_outbound::proxy::DirectMark;
use regex::Regex;
use std::{net::IpAddr, sync::Arc};

mod fingerprint;
mod geo;
mod ir;
#[cfg(any(feature = "ebpf", test))]
mod lan_protection;
mod lpm;

#[cfg(feature = "native-api")]
pub(crate) mod native;
#[cfg(feature = "native-api")]
pub(crate) use geo::GeoAssetSnapshot;
pub(crate) use geo::{GeoAssets, GeoRequirements, GeoSourceSet};
pub(crate) use ir::SharedMatchers;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAction {
    pub outbound: String,
    pub must: bool,
    pub mark: Option<DirectMark>,
    pub direct_mark_index: Option<u8>,
}

impl RouteAction {
    pub fn is_terminal_direct_mark(&self) -> bool {
        self.must && self.outbound == "direct" && self.mark.is_some()
    }
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
    pub action: RouteAction,
    /// The configured conditions as dae text, bounded; rendered once here so
    /// every API projection shows the same spelling without touching matchers.
    pub expression: String,
    /// Source-spelled conditions in compiled order; never expanded GeoIP networks.
    #[cfg(feature = "native-api")]
    pub condition_expressions: Vec<String>,
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
        self.matches_bounded::<false>(domain, &lowercase(domain), None)
    }

    fn matches_bounded<const BOUNDED: bool>(
        &self,
        domain: &str,
        lower: &str,
        deadline: Option<std::time::Instant>,
    ) -> bool {
        if self.full.contains(lower) {
            return true;
        }
        // Dot-boundary suffix walk: check the host itself, then each parent.
        if !self.suffix.is_empty() {
            let mut d = lower;
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
        bounded_any::<BOUNDED, _>(&self.regex, deadline, |re| re.is_match(domain))
    }
}

type DomainMatcherKey = Vec<(u8, String)>;

/// One `domain(...)` call. Every entry, including expanded geosite codes, is
/// an alternative: dae ORs the arguments of a single call.
#[derive(Debug, Clone)]
struct DomainMatcher {
    patterns: Vec<Regex>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
    /// One matcher per configured selector, matched as their union.
    geosite: Vec<Arc<GeositeMatcher>>,
}

impl DomainMatcher {
    fn new(
        domains: &[String],
        suffixes: &[String],
        keywords: &[String],
        regexes: &[String],
        geosite: &[GeositeDomain],
        matchers: Vec<Arc<GeositeMatcher>>,
    ) -> anyhow::Result<(DomainMatcherKey, Self)> {
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
        let mut key = patterns
            .iter()
            .map(|pattern| (0, pattern.as_str().to_owned()))
            .chain(suffixes.iter().cloned().map(|value| (1, value)))
            .chain(keywords.iter().cloned().map(|value| (2, value)))
            .chain(geosite.iter().map(|domain| match domain {
                GeositeDomain::Full(value) => (3, value.to_lowercase()),
                GeositeDomain::Domain(value) => (4, value.to_lowercase()),
                GeositeDomain::Keyword(value) => (5, value.clone()),
                GeositeDomain::Regex(value) => (6, value.as_str().to_owned()),
            }))
            .collect::<Vec<_>>();
        key.sort();
        key.dedup();
        Ok((
            key,
            Self {
                patterns,
                suffixes: suffixes.to_vec(),
                keywords: keywords.to_vec(),
                geosite: matchers,
            },
        ))
    }

    fn matches(&self, domain: &str) -> bool {
        self.matches_bounded::<false>(domain, None)
    }

    fn matches_bounded<const BOUNDED: bool>(
        &self,
        domain: &str,
        deadline: Option<std::time::Instant>,
    ) -> bool {
        bounded_any::<BOUNDED, _>(&self.patterns, deadline, |pattern| pattern.is_match(domain))
            || bounded_any::<BOUNDED, _>(&self.suffixes, deadline, |suffix| {
                domain.ends_with(suffix)
            })
            || bounded_any::<BOUNDED, _>(&self.keywords, deadline, |keyword| {
                domain.contains(keyword)
            })
            || (!self.geosite.is_empty() && {
                let lower = lowercase(domain);
                bounded_any::<BOUNDED, _>(&self.geosite, deadline, |matcher| {
                    matcher.matches_bounded::<BOUNDED>(domain, &lower, deadline)
                })
            })
    }
}

// The untimed production specialization has no clock reads or per-alternative budget branch.
fn bounded_any<const BOUNDED: bool, T>(
    values: &[T],
    deadline: Option<std::time::Instant>,
    mut matches: impl FnMut(&T) -> bool,
) -> bool {
    values
        .iter()
        .take_while(|_| !BOUNDED || deadline.is_some_and(|end| std::time::Instant::now() < end))
        .any(&mut matches)
}

/// Geosite sets are stored lowercased; query names almost always already are.
fn lowercase(domain: &str) -> std::borrow::Cow<'_, str> {
    if domain
        .bytes()
        .any(|b| b.is_ascii_uppercase() || !b.is_ascii())
    {
        std::borrow::Cow::Owned(domain.to_lowercase())
    } else {
        std::borrow::Cow::Borrowed(domain)
    }
}

/// Keys copy each matcher's whole expansion and are read only by interning and
/// the policy fingerprint, so the built router keeps just `matchers`.
#[derive(Debug, Default)]
struct DomainRegistry {
    keys: Vec<DomainMatcherKey>,
    matchers: Vec<DomainMatcher>,
}

impl DomainRegistry {
    fn intern(&mut self, (key, matcher): (DomainMatcherKey, DomainMatcher)) -> anyhow::Result<u32> {
        if let Some(id) = self.keys.iter().position(|candidate| *candidate == key) {
            return Ok(id as u32);
        }
        anyhow::ensure!(
            self.matchers.len() < ROUTING_FACT_CAPACITY,
            "routing policy has more than {ROUTING_FACT_CAPACITY} domain predicates"
        );
        let id = self.matchers.len() as u32;
        self.keys.push(key);
        self.matchers.push(matcher);
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

#[derive(Clone, Copy)]
pub(crate) struct PredicateInput<'a> {
    pub(crate) domain: Option<&'a str>,
    pub(crate) dst_ip: Option<IpAddr>,
    pub(crate) dst_port: Option<u16>,
    pub(crate) src_ip: Option<IpAddr>,
    pub(crate) src_port: Option<u16>,
    pub(crate) protocol: &'a str,
    pub(crate) process_name: Option<&'a str>,
    pub(crate) mac: Option<&'a str>,
    pub(crate) dscp: Option<u8>,
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
    #[cfg(feature = "native-api")]
    geo_assets: Arc<[GeoAssetSnapshot]>,
}

impl CompiledRoutes {
    fn new(
        routes: Vec<CompiledRoute>,
        geo_fingerprint: [u8; 32],
        #[cfg(feature = "native-api")] geo_assets: Vec<GeoAssetSnapshot>,
        geo_requirements: GeoRequirements,
    ) -> Self {
        Self {
            routes: routes.into(),
            geo_fingerprint,
            geo_requirements,
            #[cfg(feature = "native-api")]
            geo_assets: geo_assets.into(),
        }
    }
}

impl From<Vec<CompiledRoute>> for CompiledRoutes {
    fn from(routes: Vec<CompiledRoute>) -> Self {
        let requirements = GeoRequirements::default();
        let sources = GeoSourceSet::load(&requirements);
        Self::new(
            routes,
            sources.fingerprint(),
            #[cfg(feature = "native-api")]
            Vec::new(),
            requirements,
        )
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
    fallback: RouteAction,
    domain_matchers: Arc<[DomainMatcher]>,
    direct_marks: Arc<[u32]>,
    policy_fingerprint: [u8; 32],
}

impl Router {
    /// Ad-hoc rule set; its fallback carries no configured `must` or mark.
    pub fn new(rules: &[RoutingRule], plain_fallback: &str) -> anyhow::Result<Self> {
        let sources = GeoSourceSet::load(&GeoRequirements::for_traffic(rules));
        Self::build(
            rules,
            RouteAction {
                outbound: plain_fallback.to_owned(),
                must: false,
                mark: None,
                direct_mark_index: None,
            },
            &sources,
            &mut SharedMatchers::default(),
        )
    }

    pub fn from_config(routing: &RoutingConfig) -> anyhow::Result<Self> {
        let sources = GeoSourceSet::load(&GeoRequirements::for_traffic(&routing.rules));
        Self::from_config_with_geo_sources(routing, &sources)
    }

    pub(crate) fn from_config_with_geo_sources(
        routing: &RoutingConfig,
        geo_sources: &GeoSourceSet,
    ) -> anyhow::Result<Self> {
        Self::from_config_sharing(routing, geo_sources, &mut SharedMatchers::default())
    }

    /// Builds with matchers shared with the other router of the same build.
    pub(crate) fn from_config_sharing(
        routing: &RoutingConfig,
        geo_sources: &GeoSourceSet,
        shared: &mut SharedMatchers,
    ) -> anyhow::Result<Self> {
        let fallback = RouteAction {
            outbound: routing.default_outbound.clone(),
            must: routing.default_must,
            mark: DirectMark::new(routing.default_mark),
            direct_mark_index: None,
        };
        Self::build(&routing.rules, fallback, geo_sources, shared)
    }

    fn build(
        rules: &[RoutingRule],
        mut fallback: RouteAction,
        geo_sources: &GeoSourceSet,
        shared: &mut SharedMatchers,
    ) -> anyhow::Result<Self> {
        let requirements = GeoRequirements::for_traffic(rules);
        let assets = GeoAssets::from_sources(&requirements, geo_sources);
        let geo_fingerprint = geo_sources.fingerprint_for(&requirements);
        let mut registry = DomainRegistry::default();
        let mut compiled = Vec::with_capacity(rules.len());

        for (source_index, rule) in rules.iter().enumerate() {
            let mut conditions = Vec::new();
            for not in [false, true] {
                append_conditions(&mut conditions, not, rule, &assets, &mut registry, shared)?;
            }

            let outbound = rule.outbound.as_str().to_owned();
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
                action: RouteAction {
                    outbound,
                    must: rule.must,
                    mark: DirectMark::new(rule.mark),
                    direct_mark_index: None,
                },
                expression: String::new(),
                #[cfg(feature = "native-api")]
                condition_expressions: Vec::new(),
            });
        }
        #[cfg(feature = "native-api")]
        for route in &mut compiled {
            route.condition_expressions = route
                .conditions
                .iter()
                .map(|condition| {
                    native::bounded_expression(native::condition_display(
                        condition,
                        &rules[route.id as usize].condition,
                    ))
                })
                .collect();
            route.expression = native::join_expressions(route.condition_expressions.iter());
        }

        // `sort_by_key` is stable, so equal priorities retain source order.
        compiled.sort_by_key(|route| route.priority);
        for (id, route) in compiled.iter_mut().enumerate() {
            route.id = id as u32;
        }
        let mut direct_marks: Vec<u32> = compiled
            .iter()
            .map(|route| &route.action)
            .chain(std::iter::once(&fallback))
            .filter(|action| action.is_terminal_direct_mark())
            .filter_map(|action| action.mark.map(DirectMark::get))
            .collect();
        direct_marks.sort_unstable();
        direct_marks.dedup();
        anyhow::ensure!(
            direct_marks.len() <= 256,
            "terminal direct mark capacity exceeded ({} > 256 distinct nonzero marks)",
            direct_marks.len()
        );
        let index_for = |action: &mut RouteAction| {
            if action.is_terminal_direct_mark() {
                action.direct_mark_index = Some(
                    direct_marks
                        .binary_search(&action.mark.unwrap().get())
                        .unwrap() as u8,
                );
            }
        };
        for route in &mut compiled {
            index_for(&mut route.action);
        }
        index_for(&mut fallback);

        let policy_fingerprint =
            fingerprint::policy(&compiled, &registry.keys, &fallback, geo_fingerprint);
        Ok(Self {
            routes: CompiledRoutes::new(
                compiled,
                geo_fingerprint,
                #[cfg(feature = "native-api")]
                geo_sources.snapshots(&requirements),
                requirements,
            ),
            fallback,
            domain_matchers: registry.matchers.into(),
            direct_marks: direct_marks.into(),
            policy_fingerprint,
        })
    }

    pub fn fallback(&self) -> &RouteAction {
        &self.fallback
    }

    /// Resolve a terminal direct packet's mark index in this immutable generation.
    pub fn direct_mark(&self, index: u8) -> Option<u32> {
        self.direct_marks.get(usize::from(index)).copied()
    }

    pub fn has_direct_marks(&self) -> bool {
        self.fallback.outbound == "direct" && self.fallback.mark.is_some()
            || self
                .routes
                .iter()
                .any(|route| route.action.outbound == "direct" && route.action.mark.is_some())
    }

    /// Whether any rule has a `pname()` condition, positive or negated.
    pub(crate) fn uses_process_name(&self) -> bool {
        self.routes.iter().any(|route| {
            route
                .conditions
                .iter()
                .any(|condition| matches!(condition.predicate, CompiledPredicate::ProcessName(_)))
        })
    }

    pub(crate) fn geo_fingerprint(&self) -> [u8; 32] {
        self.routes.geo_fingerprint
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn geo_assets(&self) -> &[GeoAssetSnapshot] {
        &self.routes.geo_assets
    }

    pub(crate) fn geo_requirements(&self) -> &GeoRequirements {
        &self.routes.geo_requirements
    }

    pub fn policy_fingerprint(&self) -> [u8; 32] {
        self.policy_fingerprint
    }

    #[cfg(test)]
    pub(crate) fn geosite_matchers(&self) -> Vec<&Arc<GeositeMatcher>> {
        self.domain_matchers
            .iter()
            .flat_map(|matcher| &matcher.geosite)
            .collect()
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
        let (action, matched) = self.route_action(conn);
        if matched.is_none() {
            tracing::debug!(
                "Connection {} → default outbound '{}'",
                conn_log_id(conn),
                action.outbound
            );
        }
        &action.outbound
    }

    /// First matching rule's action, else the configured fallback action.
    pub fn route_action<'a>(
        &'a self,
        conn: &ConnectionInfo,
    ) -> (&'a RouteAction, Option<RouteMatch<'a>>) {
        match self.route_full(conn) {
            Some(hit) => (hit.action, Some(hit)),
            None => (self.fallback(), None),
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
        self.route_full_with_observer(conn, domain_bitmap, |_, _, _| {})
    }

    #[inline]
    fn route_full_with_observer<'a>(
        &'a self,
        conn: &ConnectionInfo,
        domain_bitmap: Option<&DomainRouting>,
        mut observe: impl FnMut(usize, Option<usize>, bool),
    ) -> Option<RouteMatch<'a>> {
        self.routes.iter().enumerate().find_map(|(index, route)| {
            let matched = self.matches_route(route, conn, domain_bitmap, |condition, matched| {
                observe(index, Some(condition), matched);
            });
            observe(index, None, matched);
            if !matched {
                return None;
            }
            tracing::debug!(
                "Connection {} matched rule '{}' → '{}' (must={}, mark={})",
                conn_log_id(conn),
                route.name,
                route.action.outbound,
                route.action.must,
                route.action.mark.map_or(0, DirectMark::get)
            );
            Some(RouteMatch {
                rule_id: route.id,
                action: &route.action,
                rule_name: &route.name,
                rule_type: &route.rule_type,
                rule_payload: &route.rule_payload,
            })
        })
    }

    fn matches_route(
        &self,
        route: &CompiledRoute,
        conn: &ConnectionInfo,
        domain_bitmap: Option<&DomainRouting>,
        mut observe: impl FnMut(usize, bool),
    ) -> bool {
        let input = PredicateInput {
            domain: conn.domain.as_deref(),
            dst_ip: Some(conn.dst_ip),
            dst_port: Some(conn.dst_port),
            src_ip: Some(conn.src_ip),
            src_port: Some(conn.src_port),
            protocol: conn.protocol,
            process_name: conn.process_name.as_deref(),
            mac: conn.mac.as_deref(),
            dscp: conn.dscp,
        };
        !route.conditions.is_empty()
            && route
                .conditions
                .iter()
                .enumerate()
                .all(|(index, condition)| {
                    // Production absence is a miss before negation; simulations retain unknown.
                    let matched = self
                        .evaluate_predicate::<false>(
                            &condition.predicate,
                            input,
                            domain_bitmap,
                            None,
                        )
                        .unwrap_or(false);
                    let matched = if condition.not { !matched } else { matched };
                    observe(index, matched);
                    matched
                })
    }

    fn evaluate_predicate<const BOUNDED: bool>(
        &self,
        predicate: &CompiledPredicate,
        input: PredicateInput<'_>,
        domain_bitmap: Option<&DomainRouting>,
        deadline: Option<std::time::Instant>,
    ) -> Option<bool> {
        match predicate {
            CompiledPredicate::Domain(id) => domain_bitmap
                .map(|bitmap| {
                    let id = *id as usize;
                    id < ROUTING_FACT_CAPACITY && bitmap.bitmap[id / 32] & (1 << (id % 32)) != 0
                })
                .or_else(|| {
                    input.domain.map(|domain| {
                        self.domain_matchers
                            .get(*id as usize)
                            .is_some_and(|matcher| {
                                matcher.matches_bounded::<BOUNDED>(domain, deadline)
                            })
                    })
                }),
            CompiledPredicate::DestinationIp(matcher) => {
                input.dst_ip.map(|ip| matcher.matches(&ip))
            }
            CompiledPredicate::SourceIp(matcher) => input.src_ip.map(|ip| matcher.matches(&ip)),
            CompiledPredicate::DestinationPort(ranges) => input.dst_port.map(|port| {
                bounded_any::<BOUNDED, _>(ranges, deadline, |range| range.contains(port))
            }),
            CompiledPredicate::SourcePort(ranges) => input.src_port.map(|port| {
                bounded_any::<BOUNDED, _>(ranges, deadline, |range| range.contains(port))
            }),
            CompiledPredicate::Protocol(mask) => Some(protocol_value(input.protocol) & *mask != 0),
            CompiledPredicate::IpVersion(mask) => input.dst_ip.map(|ip| {
                let version = if ip.is_ipv4() { 1 } else { 2 };
                *mask & version != 0
            }),
            CompiledPredicate::Dscp(values) => input
                .dscp
                .map(|dscp| bounded_any::<BOUNDED, _>(values, deadline, |value| *value == dscp)),
            CompiledPredicate::ProcessName(patterns) => input.process_name.map(|name| {
                bounded_any::<BOUNDED, _>(patterns, deadline, |pattern| name.contains(pattern))
            }),
            CompiledPredicate::Mac(macs) => input.mac.map(|mac| {
                normalize_mac_bytes(mac).is_some_and(|mac| {
                    bounded_any::<BOUNDED, _>(macs, deadline, |value| *value == mac)
                })
            }),
        }
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    pub fn compiled_routes(&self) -> &[CompiledRoute] {
        self.routes.as_ref()
    }

    pub(crate) fn ip_matchers(&self) -> impl Iterator<Item = &Arc<IpMatcher>> {
        self.compiled_routes()
            .iter()
            .flat_map(|route| &route.conditions)
            .filter_map(|condition| match &condition.predicate {
                CompiledPredicate::DestinationIp(matcher)
                | CompiledPredicate::SourceIp(matcher) => Some(matcher),
                _ => None,
            })
    }
}

#[derive(Debug, Clone)]
pub struct RouteMatch<'a> {
    pub rule_id: u32,
    pub action: &'a RouteAction,
    pub rule_name: &'a str,
    pub rule_type: &'a str,
    pub rule_payload: &'a str,
}

fn append_conditions(
    conditions: &mut Vec<CompiledCondition>,
    not: bool,
    rule: &RoutingRule,
    assets: &GeoAssets,
    registry: &mut DomainRegistry,
    shared: &mut SharedMatchers,
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
        || !geosites.is_empty()
    {
        let (mut geosite_domains, mut matchers) = (Vec::new(), Vec::new());
        for code in geosites {
            let selected = assets.geosite_domains(std::slice::from_ref(code));
            matchers.push(shared.geosite(code, &selected));
            geosite_domains.extend(selected);
        }
        let id = registry.intern(DomainMatcher::new(
            domains,
            domain_suffixes,
            domain_keywords,
            domain_regex,
            &geosite_domains,
            matchers,
        )?)?;
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
            predicate: CompiledPredicate::DestinationIp(shared.ip(nets)),
        });
    }
    if !source_ips.is_empty() {
        let nets = source_ips
            .iter()
            .filter_map(|value| parse_ip_net_str(value))
            .collect();
        conditions.push(CompiledCondition {
            not,
            predicate: CompiledPredicate::SourceIp(shared.ip(nets)),
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
                    .filter_map(|value| {
                        let value = value.trim();
                        value
                            .strip_prefix("0x")
                            .or_else(|| value.strip_prefix("0X"))
                            .map_or_else(|| value.parse(), |hex| u8::from_str_radix(hex, 16))
                            .ok()
                    })
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

fn parse_ip_version(s: &str) -> Option<u8> {
    match s.trim().to_lowercase().as_str() {
        "4" | "ipv4" => Some(4),
        "6" | "ipv6" => Some(6),
        _ => None,
    }
}

/// Decode a dae IP host or CIDR using the shared configuration conversion.
pub(crate) fn parse_ip_net_str(s: &str) -> Option<ipnet::IpNet> {
    honk_config::dns::decode_ip_or_cidr(s).map(|decoded| decoded.network)
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
