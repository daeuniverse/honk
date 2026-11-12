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
        let target_query = retarget_query(raw_query, parsed.query(), target)?;
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
        let response = alias_response(raw_query, parsed.query(), chain, target.reusable())?;
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

fn retarget_query(
    raw_query: &[u8],
    query: &QueryContext,
    target: &str,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        raw_query[4..10] == [0, 1, 0, 0, 0, 0]
            && matches!(&raw_query[10..12], [0, 0] | [0, 1]),
        "unsupported hosts alias query sections"
    );
    let question_end = query
        .question_offsets()
        .context("hosts alias query has no question")?
        .end();
    let opt_fields = if raw_query[10..12] == [0, 1] {
        let mut name = [0; 255];
        let (length, fields) = parse_name_into(raw_query, question_end, &mut name)?;
        anyhow::ensure!(
            name[..length] == [0] && raw_query[fields..fields + 2] == [0, 41],
            "unsupported hosts alias query additional record"
        );
        Some(fields)
    } else {
        None
    };
    let mut retargeted = Vec::with_capacity(raw_query.len() + target.len() + 2);
    retargeted.extend_from_slice(&raw_query[..12]);
    append_name(&mut retargeted, target);
    retargeted.extend_from_slice(&raw_query[question_end - 4..question_end]);
    if let Some(fields) = opt_fields {
        // The old root owner may be compressed into the replaced question.
        retargeted.push(0);
        retargeted.extend_from_slice(&raw_query[fields..]);
    }
    Ok(retargeted)
}

/// RFC 6604: the RCODE describes the last name in the chain, so a target
/// NXDOMAIN still carries the CNAME records of the names that do exist. Any
/// other failure code is passed through without records.
fn alias_response(
    raw_query: &[u8],
    query: &QueryContext,
    chain: &[&str],
    target: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let rcode = crate::dns::response::response_rcode(target)?;
    let rcode = if rcode > 15 && query.edns().is_none() { 2 } else { rcode };
    let (mut response, question_name) = response_prefix(
        raw_query,
        query,
        (rcode & 0x0f) as u8,
        target.len().saturating_add(chain.len() * 64),
    );
    if crate::dns::response::is_truncated(target) {
        response[2] |= 0x02;
    }
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
    append_edns(&mut response, query, rcode);
    Ok(response)
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
mod tests;
