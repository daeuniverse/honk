//! Immutable system or OxiDNS-compatible hosts snapshots for one DNS runtime generation.
//!
//! Loading happens while a generation is built, so SIGHUP publishes hosts,
//! policy, transports, and routing together. Query handling performs no file I/O.
//! A rule may name one domain instead of addresses (a honk extension): the
//! name then answers as a CNAME to that domain, which resolves normally.

use anyhow::Context;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Read as _;
use std::net::IpAddr;
#[cfg(test)]
use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use regex::Regex;

use crate::dns::cache::PublicationEpoch;
use crate::dns::engine::pipeline::{ResolveExecution, resolve_with_owner};
use crate::dns::engine::{DnsEngine, ParsedQuery};
use crate::dns::outcome::DnsOutcome;
use crate::dns::query::{DnsRequestMeta, IngressProfile, QueryContext, parse_name_into};

use super::response::{append_edns, make_address_response, response_prefix};
use super::{DnsForwardError, DnsForwarder, ResolveMode, ResolveOptions};

const HOSTS_TTL_SECS: u32 = 60;
/// Longest chain of hosts aliases one lookup follows; a loop always exceeds it.
const MAX_ALIAS_DEPTH: usize = 8;

#[derive(Debug, Default)]
pub(crate) struct HostsFile {
    entries: HashMap<String, HostsTarget>,
    rules: Vec<HostsRule>,
    /// Lets node-host lookups decline without normalizing the host when no
    /// rule is an alias.
    has_aliases: bool,
}

#[derive(Debug, PartialEq)]
enum HostsTarget {
    Addresses(Vec<IpAddr>),
    Alias(String),
}

/// What a hosts match means for one DNS query.
#[allow(clippy::large_enum_variant)] // matched at once; boxing would allocate per hosts answer
pub(crate) enum HostsResolution<'h> {
    Answered(DnsOutcome),
    /// The alias targets in chain order; the last one is resolved normally.
    Alias(Vec<&'h str>),
}

/// Where a hosts alias sends a node server host.
pub(crate) enum NodeHostAlias {
    Addresses(Vec<IpAddr>),
    Name(String),
}

#[derive(Clone)]
pub(crate) struct HostsSnapshot {
    fingerprint: [u8; 32],
    hosts: Option<Arc<HostsFile>>,
}

pub(crate) struct HostsSourceSet {
    fingerprint: [u8; 32],
    sources: Vec<(bool, String)>,
}

impl Default for HostsSnapshot {
    fn default() -> Self {
        Self {
            fingerprint: Sha256::digest([]).into(),
            hosts: None,
        }
    }
}

impl HostsSnapshot {
    pub(crate) fn new(fingerprint: [u8; 32], hosts: Option<Arc<HostsFile>>) -> Self {
        Self { fingerprint, hosts }
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

impl HostsSourceSet {
    pub(crate) fn load(config: &honk_config::dns::DnsConfig) -> anyhow::Result<Self> {
        Self::load_captured(config, |source| {
            let path = honk_config::paths::resolve_dependency_path(source);
            fs::read_to_string(&path)
                .map_err(anyhow::Error::new)
                .with_context(|| format!("failed to load DNS hosts file {}", path.display()))
        })
    }

    pub(crate) fn load_captured<E>(
        config: &honk_config::dns::DnsConfig,
        mut read: impl FnMut(&str) -> Result<String, E>,
    ) -> Result<Self, E> {
        let mut hash = Sha256::new();
        let mut sources = Vec::with_capacity(config.hosts.len());
        for source in &config.hosts {
            let rules = source != honk_config::dns::SYSTEM_HOSTS_PATH;
            let contents = read(source)?;
            update_hash(&mut hash, &[u8::from(rules)]);
            update_hash(&mut hash, &Sha256::digest(contents.as_bytes()));
            sources.push((rules, contents));
        }
        Ok(Self {
            fingerprint: hash.finalize().into(),
            sources,
        })
    }

    pub(crate) fn probe_fingerprint(
        config: &honk_config::dns::DnsConfig,
    ) -> anyhow::Result<[u8; 32]> {
        let mut hash = Sha256::new();
        for source in &config.hosts {
            let rules = source != honk_config::dns::SYSTEM_HOSTS_PATH;
            let path = honk_config::paths::resolve_dependency_path(source);
            let digest = digest_file(&path)
                .map_err(anyhow::Error::new)
                .with_context(|| format!("failed to load DNS hosts file {}", path.display()))?;
            update_hash(&mut hash, &[u8::from(rules)]);
            update_hash(&mut hash, &digest);
        }
        Ok(hash.finalize().into())
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub(crate) fn parse(self) -> io::Result<HostsSnapshot> {
        let mut hosts = HostsFile::default();
        for (rules, contents) in self.sources {
            let loaded = if rules {
                HostsFile::parse_rules(&contents)?
            } else {
                HostsFile::parse(&contents)
            };
            hosts.merge(loaded);
        }
        hosts.check_alias_chains()?;
        Ok(HostsSnapshot {
            fingerprint: self.fingerprint,
            hosts: (!hosts.entries.is_empty() || !hosts.rules.is_empty()).then(|| Arc::new(hosts)),
        })
    }
}

fn update_hash(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn digest_file(path: &std::path::Path) -> io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(hash.finalize().into());
        }
        hash.update(&buffer[..read]);
    }
}

#[derive(Debug)]
struct HostsRule {
    matcher: HostsMatcher,
    target: HostsTarget,
}

#[derive(Debug)]
enum HostsMatcher {
    Domain(String),
    Keyword(String),
    Regexp(String, Regex),
}

impl HostsMatcher {
    fn same_pattern(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Domain(left), Self::Domain(right))
            | (Self::Keyword(left), Self::Keyword(right))
            | (Self::Regexp(left, _), Self::Regexp(right, _)) => left == right,
            _ => false,
        }
    }
}

impl std::fmt::Display for HostsMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(suffix) => write!(f, "domain:{suffix}"),
            Self::Keyword(keyword) => write!(f, "keyword:{keyword}"),
            Self::Regexp(pattern, _) => write!(f, "regexp:{pattern}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum AliasChainError {
    #[error("loops")]
    Loop,
    #[error("is longer than {} aliases", MAX_ALIAS_DEPTH)]
    TooLong,
}

impl HostsSnapshot {
    pub(crate) fn hosts(&self) -> Option<Arc<HostsFile>> {
        self.hosts.clone()
    }
}

impl HostsFile {
    #[cfg(test)]
    pub(super) fn load(path: &Path) -> io::Result<Self> {
        fs::read_to_string(path).map(|contents| Self::parse(&contents))
    }

    pub(super) fn merge(&mut self, other: Self) {
        self.entries.extend(other.entries);
        for rule in other.rules {
            self.insert_rule(rule.matcher, rule.target);
        }
        self.has_aliases = self.contains_alias();
    }

    fn contains_alias(&self) -> bool {
        self.entries
            .values()
            .chain(self.rules.iter().map(|rule| &rule.target))
            .any(|target| matches!(target, HostsTarget::Alias(_)))
    }

    /// Every lookup's chain continues through the chain of some alias target,
    /// so bounding those here leaves the query-time bound as a defence only.
    fn check_alias_chains(&self) -> io::Result<()> {
        let invalid = |matcher: &dyn std::fmt::Display, first: &str, error: AliasChainError| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid hosts alias {matcher} -> {first}: the chain {error}"),
            )
        };
        for (name, target) in &self.entries {
            if let HostsTarget::Alias(first) = target {
                self.follow_aliases(first)
                    .map_err(|error| invalid(&format_args!("full:{name}"), first, error))?;
            }
        }
        for rule in &self.rules {
            if let HostsTarget::Alias(first) = &rule.target {
                self.follow_aliases(first)
                    .map_err(|error| invalid(&rule.matcher, first, error))?;
            }
        }
        Ok(())
    }

    fn parse(contents: &str) -> Self {
        let mut entries: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for line in contents.lines() {
            let fields = line
                .split_once('#')
                .map_or(line, |(record, _)| record)
                .split_whitespace();
            let mut fields = fields;
            let Some(address) = fields.next().and_then(|value| value.parse::<IpAddr>().ok()) else {
                continue;
            };
            for hostname in fields {
                let hostname = normalize_hostname(hostname);
                if hostname.is_empty() {
                    continue;
                }
                let addresses = entries.entry(hostname).or_default();
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        Self {
            entries: entries
                .into_iter()
                .map(|(hostname, addresses)| (hostname, HostsTarget::Addresses(addresses)))
                .collect(),
            rules: Vec::new(),
            has_aliases: false,
        }
    }

    fn parse_rules(contents: &str) -> io::Result<Self> {
        let mut hosts = Self::default();
        for (index, line) in contents.lines().enumerate() {
            let record = line
                .split_once('#')
                .map_or(line, |(record, _)| record)
                .trim();
            if record.is_empty() {
                continue;
            }

            let line_number = index + 1;
            let mut fields = record.split_whitespace();
            let matcher = fields.next().expect("non-empty hosts rule");
            let target = parse_target(fields, line_number)?;

            if let Some(value) = matcher.strip_prefix("domain:") {
                hosts.insert_rule(
                    HostsMatcher::Domain(normalize_rule_name(value, line_number)?),
                    target,
                );
            } else if let Some(value) = matcher.strip_prefix("keyword:") {
                hosts.insert_rule(
                    HostsMatcher::Keyword(normalize_rule_name(value, line_number)?),
                    target,
                );
            } else if let Some(value) = matcher.strip_prefix("regexp:") {
                let regex = Regex::new(value).map_err(|error| {
                    invalid_rule(line_number, format!("invalid regexp {value:?}: {error}"))
                })?;
                hosts.insert_rule(HostsMatcher::Regexp(value.to_owned(), regex), target);
            } else {
                let value = matcher.strip_prefix("full:").unwrap_or(matcher);
                let name = normalize_rule_name(value, line_number)?;
                if matches!(&target, HostsTarget::Alias(alias) if *alias == name) {
                    return Err(invalid_rule(line_number, "alias names itself"));
                }
                hosts.entries.insert(name, target);
            }
        }
        hosts.has_aliases = hosts.contains_alias();
        Ok(hosts)
    }

    fn insert_rule(&mut self, matcher: HostsMatcher, target: HostsTarget) {
        if let Some(rule) = self
            .rules
            .iter_mut()
            .find(|rule| rule.matcher.same_pattern(&matcher))
        {
            rule.target = target;
        } else {
            self.rules.push(HostsRule { matcher, target });
        }
    }

    #[cfg(test)]
    fn addresses_for(&self, domain: &str) -> Option<&[IpAddr]> {
        match self.target_for(domain)? {
            HostsTarget::Addresses(addresses) => Some(addresses),
            HostsTarget::Alias(_) => None,
        }
    }

    fn target_for(&self, domain: &str) -> Option<&HostsTarget> {
        if let Some(target) = self.entries.get(domain) {
            return Some(target);
        }

        // ponytail: pattern rules stay linear until real hosts files make this visible in profiles.
        if let Some(rule) = self
            .rules
            .iter()
            .filter(|rule| {
                matches!(
                    &rule.matcher,
                    HostsMatcher::Domain(suffix) if domain_matches(domain, suffix)
                )
            })
            .max_by_key(|rule| match &rule.matcher {
                HostsMatcher::Domain(suffix) => suffix.len(),
                _ => 0,
            })
        {
            return Some(&rule.target);
        }
        if let Some(rule) = self.rules.iter().find(|rule| {
            matches!(&rule.matcher, HostsMatcher::Regexp(_, regex) if regex.is_match(domain))
        }) {
            return Some(&rule.target);
        }
        self.rules.iter().find_map(|rule| match &rule.matcher {
            HostsMatcher::Keyword(keyword) if domain.contains(keyword) => Some(&rule.target),
            _ => None,
        })
    }

    fn alias_chain<'h>(&'h self, domain: &str, first: &'h str) -> anyhow::Result<Vec<&'h str>> {
        self.follow_aliases(first)
            .map_err(|error| anyhow::anyhow!("hosts alias chain from {domain} {error}"))
    }

    fn follow_aliases<'h>(&'h self, first: &'h str) -> Result<Vec<&'h str>, AliasChainError> {
        let mut chain = vec![first];
        while let Some(HostsTarget::Alias(next)) = self.target_for(chain[chain.len() - 1]) {
            if chain.contains(&next.as_str()) {
                return Err(AliasChainError::Loop);
            }
            if chain.len() == MAX_ALIAS_DEPTH {
                return Err(AliasChainError::TooLong);
            }
            chain.push(next);
        }
        Ok(chain)
    }

    fn resolution<'h>(
        &'h self,
        raw_query: &[u8],
        parsed: &ParsedQuery,
    ) -> Option<anyhow::Result<HostsAnswer<'h>>> {
        if parsed.query().qclass()?.get() != 1 || !matches!(parsed.qtype(), 1 | 28) {
            return None;
        }
        Some(match self.target_for(parsed.domain())? {
            HostsTarget::Addresses(addresses) => Ok(HostsAnswer::Response(make_address_response(
                raw_query,
                parsed.query(),
                addresses,
                HOSTS_TTL_SECS,
            ))),
            HostsTarget::Alias(first) => self
                .alias_chain(parsed.domain(), first)
                .map(HostsAnswer::Alias),
        })
    }
}

enum HostsAnswer<'h> {
    Response(Vec<u8>),
    Alias(Vec<&'h str>),
}

/// A rule's targets: addresses, or exactly one domain name as an alias.
fn parse_target<'a>(
    mut values: impl Iterator<Item = &'a str>,
    line: usize,
) -> io::Result<HostsTarget> {
    let Some(first) = values.next() else {
        return Err(invalid_rule(line, "rule contains no IP address or alias"));
    };
    if first.parse::<IpAddr>().is_err() {
        let alias = normalize_hostname(first);
        if !is_hostname(&alias) {
            return Err(invalid_rule(line, format!("invalid IP or alias {first:?}")));
        }
        if values.next().is_some() {
            return Err(invalid_rule(
                line,
                format!("alias {first:?} must be the only target"),
            ));
        }
        return Ok(HostsTarget::Alias(alias));
    }
    let mut addresses = Vec::new();
    for value in std::iter::once(first).chain(values) {
        let address = value
            .parse::<IpAddr>()
            .map_err(|error| invalid_rule(line, format!("invalid IP {value:?}: {error}")))?;
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(HostsTarget::Addresses(addresses))
}

/// Whether `name` can be an alias target. A last label of digits only is a
/// mistyped IPv4 address, not a name.
fn is_hostname(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        && !name
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
}

fn normalize_rule_name(value: &str, line: usize) -> io::Result<String> {
    let value = normalize_hostname(value);
    if value.is_empty() {
        Err(invalid_rule(line, "empty matcher"))
    } else {
        Ok(value)
    }
}

fn invalid_rule(line: usize, reason: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid hosts rule on line {line}: {reason}"),
    )
}

fn domain_matches(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || domain
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn normalize_hostname(hostname: &str) -> String {
    let mut hostname = hostname.trim_end_matches('.').to_owned();
    hostname.make_ascii_lowercase();
    hostname
}

impl DnsForwarder {
    pub(crate) fn resolve_hosts(
        &self,
        engine: &DnsEngine,
        parsed: &ParsedQuery,
        raw_query: &[u8],
        mode: ResolveMode,
    ) -> Result<Option<HostsResolution<'_>>, DnsForwardError> {
        let Some(answer) = self
            .hosts
            .as_deref()
            .and_then(|hosts| hosts.resolution(raw_query, parsed))
        else {
            return Ok(None);
        };
        match answer {
            Ok(HostsAnswer::Response(response)) => self
                .local_outcome_from_wire(engine, parsed, response, mode)
                .map(|outcome| Some(HostsResolution::Answered(outcome))),
            Ok(HostsAnswer::Alias(chain)) => Ok(Some(HostsResolution::Alias(chain))),
            Err(error) => {
                crate::logging::warn_throttled!(
                    error = %format_args!("{error:#}"),
                    "DNS hosts alias failed"
                );
                Err(error.into())
            }
        }
    }

    /// Answer an alias with its CNAME chain followed by the answer records of
    /// the last target, which resolves through the whole pipeline. The
    /// composed answer is local, so it bypasses the cache like other hosts
    /// answers; the target's own lookup does not.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn resolve_hosts_alias(
        &self,
        engine: &DnsEngine,
        parsed: &ParsedQuery,
        raw_query: &[u8],
        chain: &[&str],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
        options: &ResolveOptions,
        mode: ResolveMode,
        publication_epoch: PublicationEpoch,
    ) -> Result<DnsOutcome, DnsForwardError> {
        let target = chain.last().expect("an alias chain names its target");
        let target_query = retarget_query(raw_query, parsed.query(), target);
        let target = resolve_with_owner(
            self,
            &target_query,
            metadata,
            ingress,
            options,
            mode,
            ResolveExecution::foreground(publication_epoch),
            None,
        )
        .await?;
        let response = alias_response(raw_query, parsed.query(), chain, target.reusable());
        self.local_outcome_from_wire(engine, parsed, response, mode)
    }

    pub(crate) fn has_hosts_aliases(&self) -> bool {
        self.hosts.as_deref().is_some_and(|hosts| hosts.has_aliases)
    }

    pub(crate) fn is_hosts_alias(&self, domain: &str) -> bool {
        self.hosts
            .as_deref()
            .is_some_and(|hosts| matches!(hosts.target_for(domain), Some(HostsTarget::Alias(_))))
    }

    /// Follow a hosts alias for a node server host. `None` unless `host` is an
    /// alias: address entries do not apply to node hosts.
    pub(crate) fn node_host_alias(&self, host: &str) -> anyhow::Result<Option<NodeHostAlias>> {
        let Some(hosts) = self.hosts.as_deref() else {
            return Ok(None);
        };
        let Some(HostsTarget::Alias(first)) = hosts.target_for(host) else {
            return Ok(None);
        };
        let target = *hosts
            .alias_chain(host, first)?
            .last()
            .expect("an alias chain names its target");
        Ok(Some(match hosts.target_for(target) {
            Some(HostsTarget::Addresses(addresses)) => NodeHostAlias::Addresses(addresses.clone()),
            _ => NodeHostAlias::Name(target.to_owned()),
        }))
    }
}

fn retarget_query(raw_query: &[u8], query: &QueryContext, target: &str) -> Vec<u8> {
    let (name_start, question_end) = query
        .question_offsets()
        .map_or((12, 12), |offsets| (offsets.start(), offsets.end()));
    let fields = question_end.saturating_sub(4).max(name_start);
    let mut retargeted = Vec::with_capacity(raw_query.len() + target.len() + 2);
    retargeted.extend_from_slice(&raw_query[..name_start]);
    append_name(&mut retargeted, target);
    retargeted.extend_from_slice(&raw_query[fields..]);
    retargeted
}

/// RFC 6604: the RCODE describes the last name in the chain, so a target
/// NXDOMAIN still carries the CNAME records of the names that do exist. Any
/// other failure code is passed through without records.
fn alias_response(
    raw_query: &[u8],
    query: &QueryContext,
    chain: &[&str],
    target: &[u8],
) -> Vec<u8> {
    let rcode = target.get(3).map_or(2, |flags| flags & 0x0f);
    let (mut response, question_name) = response_prefix(
        raw_query,
        query,
        rcode,
        target.len().saturating_add(chain.len() * 64),
    );
    if matches!(rcode, 0 | 3) {
        let qtype = query.qtype().map_or(0, |qtype| qtype.get());
        let mut owner = None;
        for &name in chain {
            match owner {
                Some(owner) => append_name(&mut response, owner),
                None => response.extend_from_slice(&question_name),
            }
            response.extend_from_slice(&5u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&HOSTS_TTL_SECS.to_be_bytes());
            response.extend_from_slice(&(name.len() as u16 + 2).to_be_bytes());
            append_name(&mut response, name);
            owner = Some(name);
        }
        let answers = chain.len() as u16 + copy_answers(&mut response, target, qtype);
        response[6..8].copy_from_slice(&answers.to_be_bytes());
    }
    append_edns(&mut response, query);
    response
}

/// Append the target's CNAME and `qtype` answer records with every name
/// expanded, since compression pointers only make sense in their own message.
fn copy_answers(response: &mut Vec<u8>, target: &[u8], qtype: u16) -> u16 {
    let Some(header) = target.get(..12) else {
        return 0;
    };
    let questions = u16::from_be_bytes([header[4], header[5]]);
    let answers = u16::from_be_bytes([header[6], header[7]]);
    let mut cursor = 12;
    for _ in 0..questions {
        if !crate::dns::wire::skip_dns_name(target, &mut cursor) {
            return 0;
        }
        cursor += 4;
    }
    let mut copied = 0u16;
    let mut name = [0; 255];
    for _ in 0..answers {
        let Ok((owner_length, fields)) = parse_name_into(target, cursor, &mut name) else {
            break;
        };
        let Some(fixed) = target.get(fields..fields + 10) else {
            break;
        };
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdata_start = fields + 10;
        let rdata_end = rdata_start + usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let Some(rdata) = target.get(rdata_start..rdata_end) else {
            break;
        };
        cursor = rdata_end;
        if record_type == 5 {
            let mut alias = [0; 255];
            let Ok((alias_length, _)) = parse_name_into(target, rdata_start, &mut alias) else {
                break;
            };
            response.extend_from_slice(&name[..owner_length]);
            response.extend_from_slice(&fixed[..8]);
            response.extend_from_slice(&(alias_length as u16).to_be_bytes());
            response.extend_from_slice(&alias[..alias_length]);
        } else if record_type == qtype {
            response.extend_from_slice(&name[..owner_length]);
            response.extend_from_slice(fixed);
            response.extend_from_slice(rdata);
        } else {
            continue;
        }
        copied += 1;
        if copied == u16::MAX - MAX_ALIAS_DEPTH as u16 {
            break;
        }
    }
    copied
}

/// `name` is a validated hostname, so every label fits its length byte.
fn append_name(wire: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use honk_config::dns::{
        DnsCond, DnsConfig, DnsDomainMatcher, DnsRequestAction, DnsRequestRule,
    };
    use tempfile::{NamedTempFile, tempdir};
    use tokio::sync::Mutex;

    use crate::dns::cache::DnsCache;
    use crate::dns::forwarder::{DnsUpstreamPool, build_dns_query};
    use crate::dns::outcome::{OutcomeStatus, Provenance, ResponseClass};
    use crate::dns::routing::DnsRouter;

    use super::super::response::make_empty_response;
    use super::*;

    #[derive(Default)]
    struct CountingUpstream {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl DnsUpstreamPool for CountingUpstream {
        async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let query = QueryContext::parse(raw_query)?;
            Ok(make_empty_response(raw_query, &query))
        }
    }

    fn hosts_file(contents: &str) -> NamedTempFile {
        let file = NamedTempFile::new().expect("temporary hosts file");
        std::fs::write(file.path(), contents).expect("write hosts file");
        file
    }

    fn test_forwarder(
        path: &Path,
        config: &DnsConfig,
        upstream: Arc<CountingUpstream>,
    ) -> DnsForwarder {
        let router = Arc::new(DnsRouter::new_from_dns_config(config).expect("DNS router"));
        let upstream: Arc<dyn DnsUpstreamPool> = upstream;
        let mut forwarder =
            DnsForwarder::new(upstream, Arc::new(Mutex::new(DnsCache::new(100))), router)
                .with_policy_from_config(config)
                .expect("DNS policy");
        forwarder.hosts = Some(Arc::new(HostsFile::load(path).expect("hosts snapshot")));
        forwarder
    }

    #[test]
    fn parser_normalizes_aliases_and_deduplicates_addresses() {
        let hosts = HostsFile::parse(
            "127.0.0.1 LOCALHOST localhost. alias # inline comment\n\
             ::1 localhost\n\
             invalid ignored\n\
             192.0.2.1 alias alias\n",
        );

        assert_eq!(
            hosts.addresses_for("localhost"),
            Some(
                [
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ]
                .as_slice()
            )
        );
        assert_eq!(
            hosts.addresses_for("alias"),
            Some(
                [
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn oxidns_rules_match_with_oxidns_precedence() {
        let hosts = HostsFile::parse_rules(
            "domain:evsm.cc 10.0.0.1\n\
             domain:sub.evsm.cc 10.0.0.2\n\
             full:que.evsm.cc 10.0.0.3\n\
             regexp:^api\\. 10.0.0.4\n\
             keyword:api 10.0.0.5\n\
             keyword:cdn 10.0.0.6\n\
             plain.test 10.0.0.7\n",
        )
        .unwrap();
        let ip = |last| IpAddr::V4(Ipv4Addr::new(10, 0, 0, last));

        assert_eq!(hosts.addresses_for("www.evsm.cc"), Some([ip(1)].as_slice()));
        assert_eq!(
            hosts.addresses_for("x.sub.evsm.cc"),
            Some([ip(2)].as_slice())
        );
        assert_eq!(hosts.addresses_for("que.evsm.cc"), Some([ip(3)].as_slice()));
        assert_eq!(
            hosts.addresses_for("api.other.test"),
            Some([ip(4)].as_slice())
        );
        assert_eq!(
            hosts.addresses_for("static.cdn.test"),
            Some([ip(6)].as_slice())
        );
        assert_eq!(hosts.addresses_for("plain.test"), Some([ip(7)].as_slice()));
        assert_eq!(hosts.addresses_for("not-evsm.cc"), None);
        assert!(HostsFile::parse_rules("regexp:[ 10.0.0.1").is_err());
    }

    #[test]
    fn oxidns_rule_file_supports_matcher_address_and_validation_forms() {
        let hosts = HostsFile::parse_rules(
            "# comment\n\
             full:FULL.TEST. 192.0.2.1 2001:db8::1 192.0.2.1 # trailing comment\n\
             bare.test 192.0.2.2\n\
             domain:SUFFIX.TEST. 192.0.2.3\n\
             regexp:(?i)^api[0-9]+\\.test$ 192.0.2.4\n\
             keyword:CDN 192.0.2.5\n\
             full:replace.test 192.0.2.6\n\
             full:replace.test 192.0.2.7\n",
        )
        .unwrap();
        let v4 = |last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last));

        assert_eq!(
            hosts.addresses_for("full.test"),
            Some([v4(1), IpAddr::V6("2001:db8::1".parse().unwrap())].as_slice())
        );
        assert_eq!(hosts.addresses_for("bare.test"), Some([v4(2)].as_slice()));
        assert_eq!(
            hosts.addresses_for("x.suffix.test"),
            Some([v4(3)].as_slice())
        );
        assert_eq!(hosts.addresses_for("api12.test"), Some([v4(4)].as_slice()));
        assert_eq!(
            hosts.addresses_for("static.cdn.test"),
            Some([v4(5)].as_slice())
        );
        assert_eq!(
            hosts.addresses_for("replace.test"),
            Some([v4(7)].as_slice())
        );

        let raw_regexp = HostsFile::parse_rules("regexp:^API\\.TEST$ 192.0.2.8\n").unwrap();
        assert_eq!(raw_regexp.addresses_for("api.test"), None);
        for invalid in [
            "full:no-address\n",
            "domain: 192.0.2.1\n",
            "full:bad-address 192.0.2.300\n",
        ] {
            assert!(
                HostsFile::parse_rules(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[tokio::test]
    async fn hosts_answers_a_and_aaaa_before_request_reject() {
        let file = hosts_file("192.0.2.10 service.test\n2001:db8::10 service.test\n");
        let upstream = Arc::new(CountingUpstream::default());
        let mut config = DnsConfig::default();
        config.routing.request.rules = vec![DnsRequestRule {
            conditions: vec![DnsCond::Qname {
                not: false,
                matchers: vec![DnsDomainMatcher::Full("service.test".into())],
            }],
            action: DnsRequestAction::Reject,
        }];
        let forwarder = test_forwarder(file.path(), &config, Arc::clone(&upstream));

        let mut a_query = build_dns_query("SERVICE.TEST", 1);
        a_query[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        let a = forwarder
            .resolve_outcome(&a_query)
            .await
            .expect("A outcome");
        let aaaa = forwarder
            .resolve_outcome(&build_dns_query("service.test", 28))
            .await
            .expect("AAAA outcome");

        assert_eq!(a.status(), OutcomeStatus::Accepted);
        assert_eq!(a.provenance(), Provenance::Fresh);
        assert_eq!(a.response_class(), ResponseClass::Positive);
        assert!(!a.expiry().is_cacheable());
        assert_eq!(&a.rendered()[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(a.answer_ips(), &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        assert_eq!(
            aaaa.answer_ips(),
            &[IpAddr::V6("2001:db8::10".parse().unwrap())]
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn known_name_family_miss_is_nodata_but_other_queries_use_upstream() {
        let file = hosts_file("192.0.2.20 ipv4-only.test\n");
        let upstream = Arc::new(CountingUpstream::default());
        let config = DnsConfig::default();
        let forwarder = test_forwarder(file.path(), &config, Arc::clone(&upstream));

        let family_miss = forwarder
            .resolve_outcome(&build_dns_query("ipv4-only.test", 28))
            .await
            .expect("AAAA outcome");
        assert_eq!(family_miss.status(), OutcomeStatus::Accepted);
        assert_eq!(family_miss.response_class(), ResponseClass::Nodata);
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);

        forwarder
            .resolve_outcome(&build_dns_query("ipv4-only.test", 16))
            .await
            .expect("TXT outcome");
        forwarder
            .resolve_outcome(&build_dns_query("unknown.test", 1))
            .await
            .expect("unknown A outcome");
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rebuilt_forwarder_loads_a_new_snapshot_without_mutating_the_old_one() {
        let file = hosts_file("192.0.2.30 reload.test\n");
        let upstream = Arc::new(CountingUpstream::default());
        let config = DnsConfig::default();
        let old = test_forwarder(file.path(), &config, Arc::clone(&upstream));

        std::fs::write(file.path(), "192.0.2.31 reload.test\n").expect("replace hosts file");
        let new = test_forwarder(file.path(), &config, Arc::clone(&upstream));

        let query = build_dns_query("reload.test", 1);
        let old_outcome = old.resolve_outcome(&query).await.expect("old snapshot");
        let new_outcome = new.resolve_outcome(&query).await.expect("new snapshot");
        assert_eq!(
            old_outcome.answer_ips(),
            &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30))]
        );
        assert_eq!(
            new_outcome.answer_ips(),
            &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31))]
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn configured_sources_merge_in_order() {
        let first = hosts_file("full:first.test 192.0.2.40\nfull:override.test 192.0.2.41\n");
        let second = hosts_file("full:second.test 192.0.2.42\nfull:override.test 192.0.2.43\n");
        let config = DnsConfig {
            hosts: vec![
                first.path().to_string_lossy().into_owned(),
                second.path().to_string_lossy().into_owned(),
            ],
            ..Default::default()
        };
        let router = Arc::new(DnsRouter::new_from_dns_config(&config).expect("DNS router"));
        let upstream: Arc<dyn DnsUpstreamPool> = Arc::new(CountingUpstream::default());
        let forwarder =
            DnsForwarder::new(upstream, Arc::new(Mutex::new(DnsCache::new(100))), router)
                .with_hosts_from_config(&config)
                .expect("merged hosts snapshot");

        for (domain, last) in [
            ("first.test", 40),
            ("second.test", 42),
            ("override.test", 43),
        ] {
            let outcome = forwarder
                .resolve_outcome(&build_dns_query(domain, 1))
                .await
                .expect("hosts outcome");
            assert_eq!(
                outcome.answer_ips(),
                &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))]
            );
        }
    }

    #[test]
    fn enabled_hosts_load_failure_is_fatal_but_disabled_hosts_skips_io() {
        let directory = tempdir().expect("temporary directory");
        let missing = directory.path().join("missing-hosts");
        let mut config = DnsConfig::default();
        let router = Arc::new(DnsRouter::new_from_dns_config(&config).expect("DNS router"));
        let upstream: Arc<dyn DnsUpstreamPool> = Arc::new(CountingUpstream::default());
        let forwarder =
            DnsForwarder::new(upstream, Arc::new(Mutex::new(DnsCache::new(100))), router);

        assert!(forwarder.clone().with_hosts_from_config(&config).is_ok());
        config.hosts.push(missing.to_string_lossy().into_owned());
        assert!(forwarder.with_hosts_from_config(&config).is_err());
    }

    /// Answers `upstream.test` with a compressed CNAME to `edge.upstream.test`
    /// and its address, `nodata.test` with NOERROR and no records,
    /// `missing.test` with NXDOMAIN, and fails `broken.test`.
    #[derive(Default)]
    struct ScriptedUpstream {
        names: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DnsUpstreamPool for ScriptedUpstream {
        async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            let query = QueryContext::parse(raw_query)?;
            let name = query.qname().unwrap().to_domain_name().unwrap();
            self.names.lock().unwrap().push(name.clone());
            let mut response = make_empty_response(raw_query, &query);
            match name.as_str() {
                "upstream.test" if query.qtype().unwrap().get() == 1 => {
                    let question_end = query.question_offsets().unwrap().end();
                    let mut answers = vec![0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 1, 44, 0, 7, 4];
                    answers.extend_from_slice(b"edge\xc0\x0c");
                    let edge = u8::try_from(question_end + 12).unwrap();
                    answers.extend_from_slice(&[0xc0, edge, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4]);
                    answers.extend_from_slice(&[198, 51, 100, 1]);
                    response.splice(question_end..question_end, answers);
                    response[6..8].copy_from_slice(&2u16.to_be_bytes());
                }
                "missing.test" => response[3] |= 3,
                "broken.test" => anyhow::bail!("scripted upstream failure"),
                _ => {}
            }
            Ok(response)
        }
    }

    fn rules_forwarder(
        rules: &str,
        strategy: honk_config::dns::DnsStrategy,
        upstream: Arc<dyn DnsUpstreamPool>,
    ) -> DnsForwarder {
        let config = DnsConfig::default();
        let router = Arc::new(DnsRouter::new_from_dns_config(&config).expect("DNS router"));
        let mut forwarder =
            DnsForwarder::new(upstream, Arc::new(Mutex::new(DnsCache::new(100))), router)
                .with_policy_from_config(&config)
                .expect("DNS policy")
                .with_strategy(strategy);
        forwarder.hosts = Some(Arc::new(
            HostsFile::parse_rules(rules).expect("hosts rules"),
        ));
        forwarder
    }

    /// `(owner, type, TTL, rdata)` of every answer record, with CNAME targets
    /// and addresses in text form.
    fn answers(wire: &[u8]) -> Vec<(String, u16, u32, String)> {
        let mut cursor = 12;
        assert!(crate::dns::wire::skip_dns_name(wire, &mut cursor));
        cursor += 4;
        let mut records = Vec::new();
        for _ in 0..u16::from_be_bytes([wire[6], wire[7]]) {
            let (owner, fields) = crate::dns::query::parse_name(wire, cursor).unwrap();
            let record_type = u16::from_be_bytes([wire[fields], wire[fields + 1]]);
            let ttl = u32::from_be_bytes(wire[fields + 4..fields + 8].try_into().unwrap());
            let length = usize::from(u16::from_be_bytes([wire[fields + 8], wire[fields + 9]]));
            let rdata = &wire[fields + 10..fields + 10 + length];
            let rdata = match record_type {
                5 => crate::dns::query::parse_name(wire, fields + 10)
                    .unwrap()
                    .0
                    .to_domain_name()
                    .unwrap(),
                1 => Ipv4Addr::from(<[u8; 4]>::try_from(rdata).unwrap()).to_string(),
                28 => Ipv6Addr::from(<[u8; 16]>::try_from(rdata).unwrap()).to_string(),
                _ => format!("{rdata:?}"),
            };
            records.push((owner.to_domain_name().unwrap(), record_type, ttl, rdata));
            cursor = fields + 10 + length;
        }
        records
    }

    fn record(owner: &str, record_type: u16, ttl: u32, rdata: &str) -> (String, u16, u32, String) {
        (owner.into(), record_type, ttl, rdata.into())
    }

    fn rcode(wire: &[u8]) -> u8 {
        wire[3] & 0x0f
    }

    #[test]
    fn alias_rules_parse_for_every_matcher_kind() {
        let hosts = HostsFile::parse_rules(
            "full:FULL.TEST TARGET.TEST.\n\
             bare.test target.test\n\
             domain:suffix.test target.test\n\
             regexp:^api\\. target.test\n\
             keyword:cdn target.test\n\
             full:literal.test 192.0.2.1\n",
        )
        .unwrap();
        let alias = HostsTarget::Alias("target.test".into());

        for name in [
            "full.test",
            "bare.test",
            "x.suffix.test",
            "api.other",
            "static.cdn.other",
        ] {
            assert_eq!(hosts.target_for(name), Some(&alias), "{name}");
        }
        assert_eq!(
            hosts.addresses_for("literal.test"),
            Some([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))].as_slice())
        );
        assert!(hosts.has_aliases);
        assert!(
            !HostsFile::parse_rules("full:a.test 192.0.2.1\n")
                .unwrap()
                .has_aliases
        );
    }

    #[test]
    fn invalid_alias_rules_report_their_line() {
        for (rules, reason) in [
            ("full:mixed.test 192.0.2.1 target.test\n", "invalid IP"),
            ("full:mixed.test target.test 192.0.2.1\n", "only target"),
            ("full:two.test one.test other.test\n", "only target"),
            ("full:bad.test bad!name\n", "invalid IP or alias"),
            ("full:typo.test 192.0.2.300\n", "invalid IP or alias"),
            ("full:short.test 10.0.1\n", "invalid IP or alias"),
            ("full:SELF.test. self.test\n", "names itself"),
            ("self.test self.test.\n", "names itself"),
        ] {
            let error = HostsFile::parse_rules(&format!("# comment\nok.test 192.0.2.1\n{rules}"))
                .expect_err(rules)
                .to_string();
            assert!(error.contains("on line 3"), "{rules:?}: {error}");
            assert!(error.contains(reason), "{rules:?}: {error}");
        }
    }

    #[test]
    fn later_definitions_replace_earlier_ones_across_target_kinds() {
        let mut hosts = HostsFile::parse_rules(
            "full:exact.test 192.0.2.1\n\
             full:exact.test target.test\n\
             domain:suffix.test target.test\n\
             domain:suffix.test 192.0.2.2\n",
        )
        .unwrap();
        assert_eq!(
            hosts.target_for("exact.test"),
            Some(&HostsTarget::Alias("target.test".into()))
        );
        assert_eq!(
            hosts.addresses_for("x.suffix.test"),
            Some([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))].as_slice())
        );

        hosts.merge(HostsFile::parse_rules("full:exact.test 192.0.2.3\n").unwrap());
        assert_eq!(
            hosts.addresses_for("exact.test"),
            Some([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3))].as_slice())
        );
    }

    #[test]
    fn system_hosts_format_still_ignores_lines_without_a_leading_address() {
        let hosts = HostsFile::parse("alias.test target.test\n192.0.2.1 target.test\n");
        assert_eq!(hosts.target_for("alias.test"), None);
        assert!(!hosts.has_aliases);
    }

    #[tokio::test]
    async fn alias_answers_a_and_aaaa_with_cname_and_hosts_target_records() {
        let upstream = Arc::new(CountingUpstream::default());
        let forwarder = rules_forwarder(
            "full:alias.test target.test\nfull:target.test 192.0.2.50 2001:db8::50\n",
            Default::default(),
            upstream.clone(),
        );

        let mut query = build_dns_query("ALIAS.test", 1);
        query[0..2].copy_from_slice(&0x4321u16.to_be_bytes());
        let a = forwarder.resolve_outcome(&query).await.expect("A outcome");
        let aaaa = forwarder
            .resolve_outcome(&build_dns_query("alias.test", 28))
            .await
            .expect("AAAA outcome");

        assert_eq!(&a.rendered()[0..2], &0x4321u16.to_be_bytes());
        assert_eq!(a.status(), OutcomeStatus::Accepted);
        assert_eq!(a.response_class(), ResponseClass::Positive);
        assert!(!a.expiry().is_cacheable());
        assert_eq!(
            answers(a.rendered()),
            [
                record("alias.test", 5, 60, "target.test"),
                record("target.test", 1, 60, "192.0.2.50"),
            ]
        );
        assert_eq!(a.answer_ips(), &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))]);
        assert_eq!(
            answers(aaaa.rendered()),
            [
                record("alias.test", 5, 60, "target.test"),
                record("target.test", 28, 60, "2001:db8::50"),
            ]
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn alias_target_resolves_through_upstream_and_only_the_target_is_cached() {
        let upstream = Arc::new(ScriptedUpstream::default());
        let forwarder = rules_forwarder(
            "domain:corp.test upstream.test\n",
            Default::default(),
            upstream.clone(),
        );
        let query = build_dns_query("www.corp.test", 1);

        let outcome = forwarder
            .resolve_outcome(&query)
            .await
            .expect("alias outcome");
        assert_eq!(rcode(outcome.rendered()), 0);
        assert_eq!(
            answers(outcome.rendered()),
            [
                record("www.corp.test", 5, 60, "upstream.test"),
                // The target's own TTL policy applies to its records.
                record("upstream.test", 5, 120, "edge.upstream.test"),
                record("edge.upstream.test", 1, 120, "198.51.100.1"),
            ]
        );
        assert!(!outcome.expiry().is_cacheable());
        assert_eq!(forwarder.cache.lock().await.len(), 1, "target entry only");

        forwarder
            .resolve_outcome(&query)
            .await
            .expect("cached target");
        assert_eq!(*upstream.names.lock().unwrap(), ["upstream.test"]);
    }

    #[tokio::test]
    async fn alias_target_nodata_nxdomain_and_failure() {
        let upstream: Arc<dyn DnsUpstreamPool> = Arc::new(ScriptedUpstream::default());
        let forwarder = rules_forwarder(
            "full:empty.test nodata.test\n\
             full:gone.test missing.test\n\
             full:down.test broken.test\n",
            Default::default(),
            upstream,
        );

        for (alias, target, expected_rcode) in [
            ("empty.test", "nodata.test", 0),
            ("gone.test", "missing.test", 3),
        ] {
            let outcome = forwarder
                .resolve_outcome(&build_dns_query(alias, 1))
                .await
                .expect("alias outcome");
            assert_eq!(rcode(outcome.rendered()), expected_rcode, "{alias}");
            assert_eq!(answers(outcome.rendered()), [record(alias, 5, 60, target)]);
            assert!(outcome.answer_ips().is_empty());
        }

        for name in ["broken.test", "down.test"] {
            assert!(
                forwarder
                    .resolve_outcome(&build_dns_query(name, 1))
                    .await
                    .is_err(),
                "{name}"
            );
        }
    }

    fn chain(hops: usize) -> String {
        let mut rules = String::new();
        for hop in 0..hops {
            rules.push_str(&format!("full:n{hop}.test n{}.test\n", hop + 1));
        }
        rules.push_str(&format!("full:n{hops}.test 192.0.2.60\n"));
        rules
    }

    fn load_sources(sources: &[&str]) -> io::Result<HostsSnapshot> {
        let config = DnsConfig {
            hosts: (0..sources.len())
                .map(|index| format!("rules-{index}"))
                .collect(),
            ..Default::default()
        };
        let mut sources = sources.iter();
        HostsSourceSet::load_captured(&config, |_| {
            Ok::<_, std::convert::Infallible>(sources.next().unwrap().to_string())
        })
        .unwrap()
        .parse()
    }

    #[test]
    fn alias_loops_and_long_chains_fail_to_load_after_merging() {
        let nine = chain(9);
        let cases: [(&[&str], &str); 6] = [
            (
                &["domain:corp.test host.corp.test\n"],
                "domain:corp.test -> host.corp.test: the chain loops",
            ),
            (
                &["keyword:cdn cdn.example.net\n"],
                "keyword:cdn -> cdn.example.net: the chain loops",
            ),
            (
                &["regexp:^api\\. api.example.net\n"],
                "regexp:^api\\. -> api.example.net: the chain loops",
            ),
            (
                &["full:a.test b.test\nfull:b.test a.test\n"],
                "the chain loops",
            ),
            (
                &["full:a.test b.test\n", "full:b.test a.test\n"],
                "the chain loops",
            ),
            (&[nine.as_str()], "the chain is longer than 8 aliases"),
        ];
        for (sources, expected) in cases {
            let error = load_sources(sources).err().expect("loaded").to_string();
            assert!(error.contains(expected), "{sources:?}: {error}");
        }

        assert!(load_sources(&[chain(8).as_str()]).is_ok());
        let replaced = load_sources(&[
            "full:a.test b.test\nfull:b.test a.test\n",
            "full:b.test 192.0.2.1\n",
        ])
        .expect("replaced loop");
        assert!(replaced.hosts().unwrap().has_aliases);
    }

    #[test]
    fn has_aliases_follows_the_final_definitions() {
        let has_aliases =
            |sources: &[&str]| load_sources(sources).unwrap().hosts().unwrap().has_aliases;

        assert!(!has_aliases(&[
            "full:a.test b.test\nfull:a.test 192.0.2.1\n"
        ]));
        assert!(!has_aliases(&[
            "full:a.test b.test\n",
            "full:a.test 192.0.2.1\n"
        ]));
        assert!(!has_aliases(&[
            "domain:a.test b.test\n",
            "domain:a.test 192.0.2.1\n"
        ]));
        assert!(has_aliases(&[
            "full:a.test b.test\n",
            "full:c.test 192.0.2.1\n"
        ]));
    }

    #[tokio::test]
    async fn alias_chains_follow_eight_hops_and_fail_beyond_or_on_a_loop() {
        let upstream = Arc::new(CountingUpstream::default());

        let two = rules_forwarder(&chain(2), Default::default(), upstream.clone());
        let outcome = two
            .resolve_outcome(&build_dns_query("n0.test", 1))
            .await
            .expect("two hops");
        assert_eq!(
            answers(outcome.rendered()),
            [
                record("n0.test", 5, 60, "n1.test"),
                record("n1.test", 5, 60, "n2.test"),
                record("n2.test", 1, 60, "192.0.2.60"),
            ]
        );

        let eight = rules_forwarder(&chain(8), Default::default(), upstream.clone());
        let outcome = eight
            .resolve_outcome(&build_dns_query("n0.test", 1))
            .await
            .expect("eight hops");
        assert_eq!(answers(outcome.rendered()).len(), 9);

        let nine = rules_forwarder(&chain(9), Default::default(), upstream.clone());
        assert!(
            nine.resolve_outcome(&build_dns_query("n0.test", 1))
                .await
                .is_err()
        );

        let looped = rules_forwarder(
            "full:a.test b.test\nfull:b.test a.test\n",
            Default::default(),
            upstream.clone(),
        );
        assert!(
            looped
                .resolve_outcome(&build_dns_query("a.test", 1))
                .await
                .is_err()
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn alias_leaves_other_qtypes_and_hard_filtered_families_alone() {
        let upstream = Arc::new(ScriptedUpstream::default());
        let forwarder = rules_forwarder(
            "full:alias.test target.test\nfull:target.test 192.0.2.70 2001:db8::70\n",
            honk_config::dns::DnsStrategy::Ipv4Only,
            upstream.clone(),
        );

        let txt = forwarder
            .resolve_outcome(&build_dns_query("alias.test", 16))
            .await
            .expect("TXT outcome");
        assert!(answers(txt.rendered()).is_empty());
        assert_eq!(*upstream.names.lock().unwrap(), ["alias.test"]);

        let aaaa = forwarder
            .resolve_outcome(&build_dns_query("alias.test", 28))
            .await
            .expect("filtered AAAA");
        assert_eq!(aaaa.status(), OutcomeStatus::Rejected);
        assert!(answers(aaaa.rendered()).is_empty());

        let a = forwarder
            .resolve_outcome(&build_dns_query("alias.test", 1))
            .await
            .expect("A outcome");
        assert_eq!(answers(a.rendered()).len(), 2);
        assert_eq!(upstream.names.lock().unwrap().len(), 1);
    }
}
