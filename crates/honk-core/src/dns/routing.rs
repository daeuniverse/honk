//! DNS request/response routing.
//!
//! Routes DNS queries by domain, qtype, logical client source, response IPs, and upstream metadata.

mod compiler {

    use honk_config::dns::{
        DnsCond, DnsDomainMatcher, DnsRequestAction, DnsRequestRouting, DnsResponseAction,
        DnsResponseRouting,
    };
    use tracing::warn;

    use super::matcher::{CompiledCond, CompiledDomainMatcher};
    use crate::routing::{
        BinaryLpmTrie, GeoAssets, GeoRequirements, GeositeMatcher, parse_ip_net_str,
    };

    #[derive(Clone)]
    pub(super) struct CompiledRequestRule {
        pub(super) conditions: Vec<CompiledCond>,
        pub(super) action: DnsRequestAction,
    }

    #[derive(Clone)]
    pub(super) struct CompiledResponseRule {
        pub(super) conditions: Vec<CompiledCond>,
        pub(super) action: DnsResponseAction,
    }

    pub(super) struct CompiledRouting {
        pub(super) request_rules: Vec<CompiledRequestRule>,
        pub(super) response_rules: Vec<CompiledResponseRule>,
    }

    pub(super) fn requirements(
        request: &DnsRequestRouting,
        response: &DnsResponseRouting,
    ) -> GeoRequirements {
        let mut requirements = GeoRequirements::default();
        for conditions in request
            .rules
            .iter()
            .map(|rule| rule.conditions.as_slice())
            .chain(response.rules.iter().map(|rule| rule.conditions.as_slice()))
        {
            collect_cond_codes(conditions, &mut requirements);
        }
        requirements
    }

    pub(super) fn compile(
        request: &DnsRequestRouting,
        response: &DnsResponseRouting,
        assets: &GeoAssets,
    ) -> anyhow::Result<CompiledRouting> {
        let request_rules = request
            .rules
            .iter()
            .map(|rule| {
                Ok(CompiledRequestRule {
                    conditions: compile_conditions(&rule.conditions, assets, true)?,
                    action: rule.action.clone(),
                })
            })
            .collect::<anyhow::Result<_>>()?;
        let response_rules = response
            .rules
            .iter()
            .map(|rule| {
                Ok(CompiledResponseRule {
                    conditions: compile_conditions(&rule.conditions, assets, false)?,
                    action: rule.action.clone(),
                })
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(CompiledRouting {
            request_rules,
            response_rules,
        })
    }

    fn collect_cond_codes(conditions: &[DnsCond], requirements: &mut GeoRequirements) {
        for condition in conditions {
            match condition {
                DnsCond::Qname { matchers, .. } => {
                    for matcher in matchers {
                        if let DnsDomainMatcher::Geosite(code) = matcher {
                            requirements.add_geosite(code);
                        }
                    }
                }
                DnsCond::Ip { geoip: codes, .. } => {
                    for code in codes {
                        requirements.add_geoip(code);
                    }
                }
                DnsCond::Sip { .. } | DnsCond::Qtype { .. } | DnsCond::Upstream { .. } => {}
            }
        }
    }

    fn compile_conditions(
        conditions: &[DnsCond],
        assets: &GeoAssets,
        allow_sip: bool,
    ) -> anyhow::Result<Vec<CompiledCond>> {
        conditions
            .iter()
            .map(|condition| match condition {
                DnsCond::Qname { not, matchers } => Ok(CompiledCond::Qname {
                    not: *not,
                    matchers: matchers
                        .iter()
                        .map(|matcher| compile_domain_matcher(matcher, assets))
                        .collect::<anyhow::Result<_>>()?,
                }),
                DnsCond::Qtype { not, types } => Ok(CompiledCond::Qtype {
                    not: *not,
                    types: types.clone(),
                }),
                DnsCond::Sip { not, cidrs } => {
                    if !allow_sip {
                        anyhow::bail!("DNS sip() condition is request-only");
                    }
                    if cidrs.is_empty() {
                        anyhow::bail!("DNS sip() condition requires at least one IP or CIDR");
                    }
                    let nets = cidrs
                        .iter()
                        .map(|value| {
                            parse_ip_net_str(value).ok_or_else(|| {
                                anyhow::anyhow!("Invalid DNS source IP or CIDR '{value}'")
                            })
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    Ok(CompiledCond::Sip { not: *not, nets })
                }
                DnsCond::Upstream { not, names } => Ok(CompiledCond::Upstream {
                    not: *not,
                    names: names.clone(),
                }),
                DnsCond::Ip { not, cidrs, geoip } => {
                    let mut nets: Vec<ipnet::IpNet> =
                        cidrs.iter().filter_map(|cidr| cidr.parse().ok()).collect();
                    nets.extend(assets.geoip_nets(geoip));
                    Ok(CompiledCond::Ip {
                        not: *not,
                        trie: BinaryLpmTrie::from_nets(&nets),
                    })
                }
            })
            .collect()
    }

    fn compile_domain_matcher(
        matcher: &DnsDomainMatcher,
        assets: &GeoAssets,
    ) -> anyhow::Result<CompiledDomainMatcher> {
        Ok(match matcher {
            DnsDomainMatcher::Full(value) => CompiledDomainMatcher::Full(value.to_lowercase()),
            DnsDomainMatcher::Suffix(value) => {
                CompiledDomainMatcher::Suffix(value.trim_start_matches('.').to_lowercase())
            }
            DnsDomainMatcher::Keyword(value) => CompiledDomainMatcher::Keyword(value.clone()),
            DnsDomainMatcher::Regex(pattern) => {
                CompiledDomainMatcher::Regex(regex::Regex::new(pattern).map_err(|error| {
                    anyhow::anyhow!("Invalid DNS regex '{}': {}", pattern, error)
                })?)
            }
            DnsDomainMatcher::Geosite(code) => {
                let domains = assets.geosite_domains(std::slice::from_ref(code));
                if domains.is_empty() {
                    warn!(
                        "geosite code '{}' expanded to 0 domains; matcher will never match",
                        code
                    );
                }
                CompiledDomainMatcher::Geosite(GeositeMatcher::build(&domains))
            }
        })
    }
}
mod config {
    use honk_config::dns::{DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsRouting};

    pub(super) fn request_upstream(action: &DnsRequestAction) -> Option<&str> {
        match action {
            DnsRequestAction::Reject | DnsRequestAction::AsIs => None,
            DnsRequestAction::Upstream(name) => Some(name),
        }
    }

    pub(super) fn response_upstream(action: &DnsResponseAction) -> Option<&str> {
        match action {
            DnsResponseAction::Accept | DnsResponseAction::Reject => None,
            DnsResponseAction::Upstream(name) => Some(name),
        }
    }

    pub(super) fn resolve_request_routing(config: &DnsRouting) -> DnsRequestRouting {
        if !config.request.rules.is_empty() {
            return config.request.clone();
        }
        if !config.rules.is_empty() {
            return config.convert_legacy_rules();
        }
        let mut request = config.request.clone();
        let uses_default = matches!(
            &request.fallback,
            DnsRequestAction::Upstream(name) if name == "default"
        );
        if uses_default && !matches!(config.fallback.as_str(), "" | "upstream" | "default") {
            request.fallback = DnsRequestAction::Upstream(config.fallback.clone());
        }
        request
    }
}
mod matcher {
    use std::net::IpAddr;

    use crate::routing::{BinaryLpmTrie, GeositeMatcher};

    #[derive(Clone)]
    pub(super) enum CompiledDomainMatcher {
        Full(String),
        Suffix(String),
        Keyword(String),
        Regex(regex::Regex),
        Geosite(GeositeMatcher),
    }

    impl CompiledDomainMatcher {
        fn matches(&self, domain: &str) -> bool {
            match self {
                Self::Full(pattern) => domain == pattern,
                Self::Suffix(suffix) => {
                    domain == suffix
                        || domain
                            .as_bytes()
                            .get(domain.len().saturating_sub(suffix.len() + 1))
                            .copied()
                            == Some(b'.')
                            && domain.ends_with(suffix)
                }
                Self::Keyword(keyword) => domain.contains(keyword),
                Self::Regex(regex) => regex.is_match(domain),
                Self::Geosite(matcher) => matcher.matches(domain),
            }
        }
    }

    #[derive(Clone)]
    pub(super) enum CompiledCond {
        Qname {
            not: bool,
            matchers: Vec<CompiledDomainMatcher>,
        },
        Qtype {
            not: bool,
            types: Vec<u16>,
        },
        Sip {
            not: bool,
            nets: Vec<ipnet::IpNet>,
        },
        Upstream {
            not: bool,
            names: Vec<String>,
        },
        Ip {
            not: bool,
            trie: BinaryLpmTrie,
        },
    }

    pub(super) struct Evaluation<'a> {
        domain: &'a str,
        qtype: u16,
        source_ip: Option<IpAddr>,
        answer_ips: &'a [IpAddr],
        from_upstream: &'a str,
    }

    pub(super) struct ResponseContext<'a> {
        pub(super) answer_ips: &'a [IpAddr],
        pub(super) from_upstream: &'a str,
    }

    impl<'a> Evaluation<'a> {
        pub(super) fn request(domain: &'a str, qtype: u16, source_ip: Option<IpAddr>) -> Self {
            Self {
                domain,
                qtype,
                source_ip,
                answer_ips: &[],
                from_upstream: "",
            }
        }

        pub(super) fn response(domain: &'a str, qtype: u16, context: ResponseContext<'a>) -> Self {
            Self {
                domain,
                qtype,
                source_ip: None,
                answer_ips: context.answer_ips,
                from_upstream: context.from_upstream,
            }
        }
    }

    pub(super) fn eval_conditions(conditions: &[CompiledCond], value: &Evaluation<'_>) -> bool {
        conditions.iter().all(|condition| {
            let (matched, negated) = match condition {
                CompiledCond::Qname { not, matchers } => (
                    matchers.iter().any(|matcher| matcher.matches(value.domain)),
                    *not,
                ),
                CompiledCond::Qtype { not, types } => (types.contains(&value.qtype), *not),
                CompiledCond::Sip { not, nets } => {
                    let Some(source_ip) = value.source_ip else {
                        return false;
                    };
                    (nets.iter().any(|net| net.contains(&source_ip)), *not)
                }
                CompiledCond::Upstream { not, names } => {
                    (names.iter().any(|name| name == value.from_upstream), *not)
                }
                CompiledCond::Ip { not, trie } => {
                    (value.answer_ips.iter().any(|ip| trie.matches(ip)), *not)
                }
            };
            matched != negated
        })
    }
}

#[cfg(test)]
mod tests;

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use honk_config::dns::{
    DnsConfig, DnsRequestAction, DnsResponseAction, DnsResponseRouting, DnsRouting,
};
use tracing::debug;

use self::compiler::{CompiledRequestRule, CompiledResponseRule, compile, requirements};
use self::config::{request_upstream, resolve_request_routing, response_upstream};
use self::matcher::{Evaluation, ResponseContext, eval_conditions};
use crate::routing::{GeoAssets, GeoRequirements, GeoSourceSet};

/// Output of request routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRequestDecision {
    Reject,
    AsIs,
    Upstream(String),
}

/// Output of response routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResponseDecision {
    Accept,
    Reject,
    Requery(String),
}

/// DNS router that selects upstreams based on domain, qtype, logical client source, and response metadata.
#[derive(Clone)]
pub struct DnsRouter {
    request_rules: Vec<CompiledRequestRule>,
    request_fallback: DnsRequestAction,
    response_rules: Vec<CompiledResponseRule>,
    response_fallback: DnsResponseAction,
    fixed_domain_ttl: HashMap<String, u32>,
    rule_count: usize,
    geo_fingerprint: [u8; 32],
    geo_requirements: GeoRequirements,
}

impl DnsRouter {
    pub fn new(config: &DnsRouting) -> anyhow::Result<Self> {
        Self::new_with_fixed_ttl(config, &HashMap::new())
    }

    pub fn new_with_fixed_ttl(
        config: &DnsRouting,
        fixed_domain_ttl: &HashMap<String, u32>,
    ) -> anyhow::Result<Self> {
        let request = resolve_request_routing(config);
        let requirements = requirements(&request, &config.response);
        let sources = GeoSourceSet::load(&requirements);
        Self::build(
            &request,
            &config.response,
            fixed_domain_ttl,
            &requirements,
            &sources,
        )
    }

    pub fn new_from_dns_config(dns_config: &DnsConfig) -> anyhow::Result<Self> {
        let request = resolve_request_routing(&dns_config.routing);
        let requirements = requirements(&request, &dns_config.routing.response);
        let sources = GeoSourceSet::load(&requirements);
        Self::build(
            &request,
            &dns_config.routing.response,
            &dns_config.fixed_domain_ttl,
            &requirements,
            &sources,
        )
    }

    pub(crate) fn geo_requirements(dns_config: &DnsConfig) -> GeoRequirements {
        let request = resolve_request_routing(&dns_config.routing);
        requirements(&request, &dns_config.routing.response)
    }

    pub(crate) fn new_with_geo_sources(
        dns_config: &DnsConfig,
        geo_sources: &GeoSourceSet,
    ) -> anyhow::Result<Self> {
        let request = resolve_request_routing(&dns_config.routing);
        let requirements = requirements(&request, &dns_config.routing.response);
        Self::build(
            &request,
            &dns_config.routing.response,
            &dns_config.fixed_domain_ttl,
            &requirements,
            geo_sources,
        )
    }

    fn build(
        request: &honk_config::dns::DnsRequestRouting,
        response: &DnsResponseRouting,
        fixed_domain_ttl: &HashMap<String, u32>,
        requirements: &GeoRequirements,
        geo_sources: &GeoSourceSet,
    ) -> anyhow::Result<Self> {
        let assets = GeoAssets::from_sources(requirements, geo_sources);
        let compiled = compile(request, response, &assets)?;
        Ok(Self {
            rule_count: compiled.request_rules.len() + compiled.response_rules.len(),
            request_rules: compiled.request_rules,
            request_fallback: request.fallback.clone(),
            response_rules: compiled.response_rules,
            response_fallback: response.fallback.clone(),
            fixed_domain_ttl: fixed_domain_ttl.clone(),
            geo_fingerprint: geo_sources.fingerprint_for(requirements),
            geo_requirements: requirements.clone(),
        })
    }

    /// Select a request route for a domain that has already been normalized to
    /// ASCII lowercase by the DNS query parser.
    pub(crate) fn select_request_normalized(
        &self,
        domain: &str,
        qtype: u16,
        source_ip: Option<IpAddr>,
    ) -> DnsRequestDecision {
        let evaluation = Evaluation::request(domain, qtype, source_ip);
        for rule in &self.request_rules {
            if eval_conditions(&rule.conditions, &evaluation) {
                debug!(qtype, action = ?rule.action, "DNS request route selected");
                return map_request_action(&rule.action);
            }
        }
        debug!(qtype, action = ?self.request_fallback, fallback = true, "DNS request route selected");
        map_request_action(&self.request_fallback)
    }

    pub fn select_request(&self, domain: &str, qtype: u16) -> DnsRequestDecision {
        self.select_request_normalized(&domain.to_ascii_lowercase(), qtype, None)
    }

    /// Select a response route for a domain that has already been normalized
    /// to ASCII lowercase by the DNS query parser.
    pub(crate) fn select_response_normalized(
        &self,
        domain: &str,
        qtype: u16,
        answer_ips: &[IpAddr],
        from_upstream: &str,
    ) -> DnsResponseDecision {
        let evaluation = Evaluation::response(
            domain,
            qtype,
            ResponseContext {
                answer_ips,
                from_upstream,
            },
        );
        for rule in &self.response_rules {
            if eval_conditions(&rule.conditions, &evaluation) {
                debug!(qtype, upstream = from_upstream, action = ?rule.action, "DNS response route selected");
                return map_response_action(&rule.action);
            }
        }
        debug!(qtype, action = ?self.response_fallback, fallback = true, "DNS response route selected");
        map_response_action(&self.response_fallback)
    }

    pub fn select_response(
        &self,
        domain: &str,
        qtype: u16,
        answer_ips: &[IpAddr],
        from_upstream: &str,
    ) -> DnsResponseDecision {
        self.select_response_normalized(
            &domain.to_ascii_lowercase(),
            qtype,
            answer_ips,
            from_upstream,
        )
    }

    pub fn fixed_ttl(&self, domain: &str) -> Option<u32> {
        self.fixed_domain_ttl.get(domain).copied()
    }

    pub(crate) fn upstream_names(&self) -> BTreeSet<String> {
        let request = self
            .request_rules
            .iter()
            .filter_map(|rule| request_upstream(&rule.action))
            .chain(request_upstream(&self.request_fallback));
        let response = self
            .response_rules
            .iter()
            .filter_map(|rule| response_upstream(&rule.action))
            .chain(response_upstream(&self.response_fallback));
        request
            .chain(response)
            .chain(std::iter::once("default"))
            .map(str::to_owned)
            .collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    pub(crate) fn geo_fingerprint(&self) -> [u8; 32] {
        self.geo_fingerprint
    }

    pub(crate) fn geo_requirements_snapshot(&self) -> &GeoRequirements {
        &self.geo_requirements
    }

    pub(crate) fn select_upstream_normalized(&self, domain: &str) -> &str {
        let evaluation = Evaluation::request(domain, 1, None);
        for rule in &self.request_rules {
            if eval_conditions(&rule.conditions, &evaluation) {
                return request_action_name(&rule.action, false);
            }
        }
        request_action_name(&self.request_fallback, true)
    }

    pub fn select_upstream(&self, domain: &str) -> &str {
        self.select_upstream_normalized(&domain.to_ascii_lowercase())
    }
}

fn map_request_action(action: &DnsRequestAction) -> DnsRequestDecision {
    match action {
        DnsRequestAction::Reject => DnsRequestDecision::Reject,
        DnsRequestAction::AsIs => DnsRequestDecision::AsIs,
        DnsRequestAction::Upstream(name) => DnsRequestDecision::Upstream(name.clone()),
    }
}

fn map_response_action(action: &DnsResponseAction) -> DnsResponseDecision {
    match action {
        DnsResponseAction::Accept => DnsResponseDecision::Accept,
        DnsResponseAction::Reject => DnsResponseDecision::Reject,
        DnsResponseAction::Upstream(name) => DnsResponseDecision::Requery(name.clone()),
    }
}

fn request_action_name(action: &DnsRequestAction, fallback: bool) -> &str {
    match action {
        DnsRequestAction::Upstream(name) => {
            debug!(upstream = %name, fallback, "DNS request route selected");
            name
        }
        DnsRequestAction::Reject => {
            debug!(action = "reject", fallback, "DNS request route selected");
            "reject"
        }
        DnsRequestAction::AsIs => {
            debug!(action = "asis", fallback, "DNS request route selected");
            "asis"
        }
    }
}
