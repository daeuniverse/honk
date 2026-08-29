//! Immutable system or OxiDNS-compatible hosts snapshots for one DNS runtime generation.
//!
//! Loading happens while a generation is built, so SIGHUP publishes hosts,
//! policy, transports, and routing together. Query handling performs no file I/O.

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

use crate::dns::engine::{DnsEngine, ParsedQuery};
use crate::dns::outcome::DnsOutcome;

use super::response::make_address_response;
use super::{DnsForwardError, DnsForwarder, ResolveMode};

const HOSTS_TTL_SECS: u32 = 60;

#[derive(Debug, Default)]
pub(crate) struct HostsFile {
    entries: HashMap<String, Vec<IpAddr>>,
    rules: Vec<HostsRule>,
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
        let mut hash = Sha256::new();
        let mut sources = Vec::with_capacity(config.hosts.len());
        for source in &config.hosts {
            let rules = source != honk_config::dns::SYSTEM_HOSTS_PATH;
            let path = honk_config::paths::resolve_dependency_path(source);
            let contents = fs::read_to_string(&path)
                .map_err(anyhow::Error::new)
                .with_context(|| format!("failed to load DNS hosts file {}", path.display()))?;
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
    addresses: Vec<IpAddr>,
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
            self.insert_rule(rule.matcher, rule.addresses);
        }
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
            entries,
            rules: Vec::new(),
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
            let mut addresses = Vec::new();
            for value in fields {
                let address = value.parse::<IpAddr>().map_err(|error| {
                    invalid_rule(line_number, format!("invalid IP {value:?}: {error}"))
                })?;
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
            if addresses.is_empty() {
                return Err(invalid_rule(line_number, "rule contains no IP address"));
            }

            if let Some(value) = matcher.strip_prefix("domain:") {
                hosts.insert_rule(
                    HostsMatcher::Domain(normalize_rule_name(value, line_number)?),
                    addresses,
                );
            } else if let Some(value) = matcher.strip_prefix("keyword:") {
                hosts.insert_rule(
                    HostsMatcher::Keyword(normalize_rule_name(value, line_number)?),
                    addresses,
                );
            } else if let Some(value) = matcher.strip_prefix("regexp:") {
                let regex = Regex::new(value).map_err(|error| {
                    invalid_rule(line_number, format!("invalid regexp {value:?}: {error}"))
                })?;
                hosts.insert_rule(HostsMatcher::Regexp(value.to_owned(), regex), addresses);
            } else {
                let value = matcher.strip_prefix("full:").unwrap_or(matcher);
                hosts
                    .entries
                    .insert(normalize_rule_name(value, line_number)?, addresses);
            }
        }
        Ok(hosts)
    }

    fn insert_rule(&mut self, matcher: HostsMatcher, addresses: Vec<IpAddr>) {
        if let Some(rule) = self
            .rules
            .iter_mut()
            .find(|rule| rule.matcher.same_pattern(&matcher))
        {
            rule.addresses = addresses;
        } else {
            self.rules.push(HostsRule { matcher, addresses });
        }
    }

    fn addresses_for(&self, domain: &str) -> Option<&[IpAddr]> {
        if let Some(addresses) = self.entries.get(domain) {
            return Some(addresses);
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
            return Some(&rule.addresses);
        }
        if let Some(rule) = self.rules.iter().find(|rule| {
            matches!(&rule.matcher, HostsMatcher::Regexp(_, regex) if regex.is_match(domain))
        }) {
            return Some(&rule.addresses);
        }
        self.rules.iter().find_map(|rule| match &rule.matcher {
            HostsMatcher::Keyword(keyword) if domain.contains(keyword) => {
                Some(rule.addresses.as_slice())
            }
            _ => None,
        })
    }

    fn response(&self, raw_query: &[u8], parsed: &ParsedQuery) -> Option<Vec<u8>> {
        if parsed.query().qclass()?.get() != 1 || !matches!(parsed.qtype(), 1 | 28) {
            return None;
        }
        let addresses = self.addresses_for(parsed.domain())?;
        Some(make_address_response(
            raw_query,
            parsed.query(),
            addresses,
            HOSTS_TTL_SECS,
        ))
    }
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
    ) -> Result<Option<DnsOutcome>, DnsForwardError> {
        let Some(response) = self
            .hosts
            .as_deref()
            .and_then(|hosts| hosts.response(raw_query, parsed))
        else {
            return Ok(None);
        };
        self.local_outcome_from_wire(engine, parsed, response, mode)
            .map(Some)
    }
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
    use crate::dns::query::QueryContext;
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
            hosts.entries.get("localhost"),
            Some(&vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ])
        );
        assert_eq!(
            hosts.entries.get("alias"),
            Some(&vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ])
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
            "full:bad-address not-an-ip\n",
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
}
