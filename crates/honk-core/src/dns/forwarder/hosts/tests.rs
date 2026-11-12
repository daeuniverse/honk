use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use honk_config::dns::{DnsCond, DnsConfig, DnsDomainMatcher, DnsRequestAction, DnsRequestRule};
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
    let forwarder = DnsForwarder::new(upstream, Arc::new(Mutex::new(DnsCache::new(100))), router)
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
    let forwarder = DnsForwarder::new(upstream, Arc::new(Mutex::new(DnsCache::new(100))), router);

    assert!(forwarder.clone().with_hosts_from_config(&config).is_ok());
    config.hosts.push(missing.to_string_lossy().into_owned());
    assert!(forwarder.with_hosts_from_config(&config).is_err());
}

/// Answers A queries for `upstream.test` with a compressed CNAME to
/// `edge.upstream.test` and its address, `nodata.test` with NOERROR and no records,
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

#[derive(Default)]
struct QueryCapture {
    queries: std::sync::Mutex<Vec<Vec<u8>>>,
}

#[async_trait]
impl DnsUpstreamPool for QueryCapture {
    async fn query(&self, _upstream_name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.queries.lock().unwrap().push(raw.to_vec());
        let query = QueryContext::parse(raw)?;
        Ok(make_empty_response(raw, &query))
    }
}

#[tokio::test]
async fn alias_rejects_unsupported_query_sections_before_io() {
    let upstream = Arc::new(QueryCapture::default());
    let forwarder = rules_forwarder(
        "full:a.test longer.example\n",
        Default::default(),
        upstream.clone(),
    );
    for (section, owner) in [
        (6, vec![0]),
        (8, vec![0]),
        (10, vec![0]),
        (10, vec![0xc0, 0x0e]),
    ] {
        let mut query = build_dns_query("a.test", 1);
        query[section..section + 2].copy_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&owner);
        query.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        assert!(QueryContext::parse(&query).is_ok());
        let error = forwarder
            .resolve_outcome(&query)
            .await
            .expect_err("unsupported section");
        assert!(
            error.to_string().contains("unsupported hosts alias query"),
            "{error}"
        );
        assert!(upstream.queries.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn alias_target_query_preserves_opt_options_flags_and_question_fields() {
    let upstream = Arc::new(QueryCapture::default());
    let forwarder = rules_forwarder(
        "full:a.test longer.example\n",
        Default::default(),
        upstream.clone(),
    );
    for qtype in [1, 28] {
        for compressed in [false, true] {
            let mut query = build_dns_query("a.test", qtype);
            query[..4].copy_from_slice(&[0x12, 0x34, 0x01, 0x30]);
            let root = query.len() - 5;
            query[10..12].copy_from_slice(&1u16.to_be_bytes());
            if compressed {
                query.extend_from_slice(&(0xc000 | root as u16).to_be_bytes());
            } else {
                query.push(0);
            }
            let opt = [
                0, 41, 0x05, 0x00, 0, 1, 0x80, 0x01, 0, 7, 0xfd, 0xe9, 0, 3, 1, 2, 3,
            ];
            query.extend_from_slice(&opt);
            assert!(!QueryContext::parse(&query).unwrap().is_cacheable());
            forwarder
                .resolve_outcome(&query)
                .await
                .expect("supported EDNS query");
            let captured = upstream.queries.lock().unwrap();
            let target = captured.last().unwrap();
            assert_eq!(&target[..12], &query[..12]);
            let parsed = QueryContext::parse(target).unwrap();
            assert_eq!(
                parsed.qname().unwrap().to_domain_name().unwrap(),
                "longer.example"
            );
            assert_eq!(parsed.qtype().unwrap().get(), qtype);
            assert_eq!(parsed.qclass().unwrap().get(), 1);
            let end = parsed.question_offsets().unwrap().end();
            assert_eq!(target[end], 0);
            assert_eq!(&target[end + 1..], &opt);
        }
    }
}

struct TruncatedUpstream;

#[async_trait]
impl DnsUpstreamPool for TruncatedUpstream {
    async fn query(&self, _upstream_name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        let query = QueryContext::parse(raw)?;
        let mut response = make_address_response(raw, &query, &["192.0.2.80".parse().unwrap()], 60);
        response[2] |= 0x06; // TC and AA: only TC belongs on the local composite.
        response[3] |= 0x20; // AD does not authenticate a locally generated alias.
        Ok(response)
    }
}

#[tokio::test]
async fn alias_preserves_small_truncated_target_without_authoritative_ips() {
    let forwarder = rules_forwarder(
        "full:alias.test target.test\n",
        Default::default(),
        Arc::new(TruncatedUpstream),
    );
    let outcome = forwarder
        .resolve_outcome_with_context_and_profile(
            &build_dns_query("alias.test", 1),
            DnsRequestMeta::EMPTY,
            IngressProfile::Udp {
                advertised_size: 512,
            },
        )
        .await
        .expect("truncated UDP outcome");
    assert!(outcome.rendered().len() < 512);
    assert!(crate::dns::response::is_truncated(outcome.rendered()));
    assert!(crate::dns::response::is_truncated(outcome.reusable()));
    assert_eq!(outcome.rendered()[2] & 0x04, 0);
    assert_eq!(outcome.rendered()[3] & 0x20, 0);
    assert!(outcome.answer_ips().is_empty());
    assert!(!outcome.expiry().is_cacheable());
}

struct ExtendedErrorUpstream(u16);

#[async_trait]
impl DnsUpstreamPool for ExtendedErrorUpstream {
    async fn query(&self, _upstream_name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        let query = QueryContext::parse(raw)?;
        let end = query.question_offsets().unwrap().end();
        let mut response = raw[..end].to_vec();
        response[2..4].copy_from_slice(&(0x8180 | (self.0 & 15)).to_be_bytes());
        response[6..12].fill(0);
        response[10..12].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, (self.0 >> 4) as u8, 0, 0, 0, 0, 0]);
        Ok(response)
    }
}

#[tokio::test]
async fn alias_preserves_extended_errors_and_emits_valid_badvers_opt() {
    for code in [16, 23] {
        let forwarder = rules_forwarder(
            "full:alias.test target.test\n",
            Default::default(),
            Arc::new(ExtendedErrorUpstream(code)),
        );
        for version in [None, Some(0), Some(1)] {
            let mut query = build_dns_query("alias.test", 1);
            if let Some(version) = version {
                query[10..12].copy_from_slice(&1u16.to_be_bytes());
                query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, version, 0x80, 0, 0, 0]);
            }
            let outcome = forwarder
                .resolve_outcome(&query)
                .await
                .expect("error outcome");
            let response = outcome.rendered();
            let decoded = QueryContext::parse(response).expect("valid error OPT");
            assert_eq!(&response[6..10], &[0, 0, 0, 0]);
            assert!(outcome.answer_ips().is_empty());
            if version.is_some() {
                let opt = decoded.edns().expect("extended error requires OPT");
                assert_eq!(
                    u16::from(opt.extended_rcode()) * 16 + u16::from(rcode(response)),
                    code
                );
                assert_eq!(opt.version(), 0);
                assert_eq!(opt.advertised_size(), 1232);
                assert!(opt.dnssec_ok());
            } else {
                assert_eq!(rcode(response), 2);
                assert!(decoded.edns().is_none());
                assert_eq!(&response[10..12], &[0, 0]);
            }
        }
    }
    let forwarder = rules_forwarder(
        "full:address.test 192.0.2.81\n",
        Default::default(),
        Arc::new(CountingUpstream::default()),
    );
    for version in [0, 1] {
        let mut query = build_dns_query("address.test", 1);
        query[10..12].copy_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, version, 0x80, 0, 0, 0]);
        let outcome = forwarder.resolve_outcome(&query).await.unwrap();
        let decoded = QueryContext::parse(outcome.rendered()).unwrap();
        assert_eq!(decoded.edns().is_some(), version == 0);
        assert_eq!(
            outcome.answer_ips(),
            &["192.0.2.81".parse::<IpAddr>().unwrap()]
        );
    }
}

struct MalformedCnameUpstream(Vec<u8>);

#[async_trait]
impl DnsUpstreamPool for MalformedCnameUpstream {
    async fn query(&self, _upstream_name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        let query = QueryContext::parse(raw)?;
        let mut response = make_address_response(raw, &query, &["192.0.2.82".parse().unwrap()], 60);
        response[6..8].copy_from_slice(&3u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60]);
        response.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        response.extend_from_slice(&self.0);
        response.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 83]);
        Ok(response)
    }
}

#[tokio::test]
async fn alias_rejects_zero_short_and_trailing_cname_rdata_without_partial_success() {
    for rdata in [vec![], vec![0xc0], vec![0, 0]] {
        let forwarder = rules_forwarder(
            "full:alias.test target.test\n",
            Default::default(),
            Arc::new(MalformedCnameUpstream(rdata.clone())),
        );
        assert!(
            forwarder
                .resolve_outcome(&build_dns_query("alias.test", 1))
                .await
                .is_err(),
            "accepted malformed CNAME RDATA {rdata:?}"
        );
    }
}

#[tokio::test]
async fn alias_keeps_target_request_and_response_rejections_without_target_identity() {
    use honk_config::dns::DnsResponseAction;

    for response_reject in [false, true] {
        let upstream = Arc::new(ScriptedUpstream::default());
        let mut config = DnsConfig::default();
        config.routing.request.rules = vec![DnsRequestRule {
            conditions: vec![DnsCond::Qname {
                not: false,
                matchers: vec![DnsDomainMatcher::Full("upstream.test".into())],
            }],
            action: if response_reject {
                DnsRequestAction::Upstream("upstream".into())
            } else {
                DnsRequestAction::Reject
            },
        }];
        if response_reject {
            config.routing.response.fallback = DnsResponseAction::Reject;
        }
        let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
        let mut forwarder = DnsForwarder::new(
            upstream.clone(),
            Arc::new(Mutex::new(DnsCache::new(100))),
            router,
        )
        .with_policy_from_config(&config)
        .unwrap();
        forwarder.hosts = Some(Arc::new(
            HostsFile::parse_rules("full:alias.test upstream.test\n").unwrap(),
        ));
        for _ in 0..2 {
            let outcome = forwarder
                .resolve_outcome(&build_dns_query("alias.test", 1))
                .await
                .unwrap();
            assert_eq!(outcome.status(), OutcomeStatus::Rejected);
            assert!(outcome.answer_ips().is_empty());
            assert_eq!(outcome.domain(), "alias.test");
            assert_eq!(outcome.qtype(), 1);
            assert!(!outcome.expiry().is_cacheable());
            assert_eq!(outcome.provenance(), Provenance::Fresh);
            assert_eq!(outcome.logical_upstream(), None);
            let target = forwarder
                .resolve_outcome(&build_dns_query("upstream.test", 1))
                .await
                .unwrap();
            assert_eq!(outcome.final_upstream(), target.final_upstream());
            assert_eq!(outcome.requery_history(), target.requery_history());
            assert_eq!(outcome.final_upstream().is_some(), response_reject);
            #[cfg(feature = "native-api")]
            {
                assert_eq!(outcome.cache_entry_id(), None);
                assert_eq!(
                    outcome.request_route().source,
                    crate::dns::outcome::RouteSource::Default
                );
                assert!(outcome.request_route().rule.is_none());
                assert_eq!(
                    target.request_route().source,
                    crate::dns::outcome::RouteSource::Routing
                );
            }
        }
        assert_eq!(
            upstream.names.lock().unwrap().len(),
            usize::from(response_reject)
        );
    }
}
