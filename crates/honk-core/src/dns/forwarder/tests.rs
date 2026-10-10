use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::*;
use crate::dns::cache::DnsCache;
use crate::dns::query::{DnsRequestMeta, IngressProfile};
use crate::dns::routing::DnsRouter;
use honk_config::dns::{DnsRouting, DnsRule};

use std::sync::atomic::{AtomicUsize, Ordering};

fn test_cache() -> Arc<Mutex<DnsCache>> {
    Arc::new(Mutex::new(DnsCache::new(100)))
}

fn test_router() -> Arc<DnsRouter> {
    Arc::new(
        DnsRouter::new(&DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .expect("test router"),
    )
}

#[cfg(target_os = "linux")]
#[test]
fn asis_socket_tolerates_only_permission_denied_mark_failure() {
    // Given
    let destination = SocketAddr::from(([127, 0, 0, 1], 53));

    // When
    let socket = new_asis_socket_with_mark(destination, |_| {
        honk_outbound::util::set_mark_result_best_effort(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected EPERM",
        )))
    });

    // Then
    assert!(socket.is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn asis_socket_propagates_non_permission_mark_failure_as_typed_error() {
    // Given
    let destination = SocketAddr::from(([127, 0, 0, 1], 53));

    // When
    let error = new_asis_socket_with_mark(destination, |_| {
        honk_outbound::util::set_mark_result_best_effort(Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "injected EINVAL",
        )))
    })
    .expect_err("non-EPERM mark failure");

    // Then
    assert!(matches!(error, AsIsExchangeError::BypassMark { .. }));
}

/// Build an A-record response for example.com with a given IP and TTL.
fn make_a_response(ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let ttl_bytes = ttl.to_be_bytes();
    vec![
        0x00,
        0x00, // ID (matches the query built by build_dns_query)
        0x81,
        0x80, // Flags: QR=1, RD=1, RA=1
        0x00,
        0x01, // QDCOUNT
        0x00,
        0x01, // ANCOUNT
        0x00,
        0x00, // NSCOUNT
        0x00,
        0x00, // ARCOUNT
        0x07,
        b'e',
        b'x',
        b'a',
        b'm',
        b'p',
        b'l',
        b'e',
        0x03,
        b'c',
        b'o',
        b'm',
        0x00,
        0x00,
        0x01, // QTYPE A
        0x00,
        0x01, // QCLASS IN
        0xc0,
        0x0c, // NAME pointer to offset 12
        0x00,
        0x01, // TYPE A
        0x00,
        0x01, // CLASS IN
        ttl_bytes[0],
        ttl_bytes[1],
        ttl_bytes[2],
        ttl_bytes[3], // TTL
        0x00,
        0x04, // RDLENGTH
        ip[0],
        ip[1],
        ip[2],
        ip[3], // RDATA
    ]
}

/// Build an A-record query for example.com (same as what prefetch uses).
fn make_a_query() -> Vec<u8> {
    build_dns_query("example.com", 1)
}

/// Build an NXDOMAIN response preserving the query question and carrying an
/// authority SOA whose TTL and MINIMUM determine the negative cache lifetime.
pub(crate) fn make_nxdomain_response(query: &[u8], soa_ttl: u32, soa_minimum: u32) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = 0x83;
    response[6..8].copy_from_slice(&0_u16.to_be_bytes()); // ANCOUNT
    response[8..10].copy_from_slice(&1_u16.to_be_bytes()); // NSCOUNT
    response[10..12].copy_from_slice(&0_u16.to_be_bytes()); // ARCOUNT

    response.extend_from_slice(&[0xc0, 0x0c]); // NAME pointer to qname
    response.extend_from_slice(&[0x00, 0x06, 0x00, 0x01]); // SOA, IN
    response.extend_from_slice(&soa_ttl.to_be_bytes());
    response.extend_from_slice(&22_u16.to_be_bytes());
    response.extend_from_slice(&[0, 0]); // Root MNAME and RNAME, followed by five u32 fields.
    for value in [1_u32, 7200, 3600, 1_209_600, soa_minimum] {
        response.extend_from_slice(&value.to_be_bytes());
    }
    response
}

fn make_nxdomain_without_soa_response(query: &[u8]) -> Vec<u8> {
    let mut response = make_nxdomain_response(query, 30, 20);
    response.truncate(query.len());
    response[8..10].copy_from_slice(&0_u16.to_be_bytes());
    response
}

fn nodata_response(domain: &str, qtype: u16, soa: Option<(u32, u32)>) -> Vec<u8> {
    let query = build_dns_query(domain, qtype);
    if let Some((ttl, minimum)) = soa {
        let mut response = make_nxdomain_response(&query, ttl, minimum);
        response[3] = 0x80;
        return response;
    }
    let context = crate::dns::query::QueryContext::parse(&query).expect("query context");
    make_empty_response(&query, &context)
}

struct MockUpstream {
    response: Vec<u8>,
    call_count: AtomicUsize,
}

impl MockUpstream {
    fn new(response: Vec<u8>) -> Self {
        Self {
            response,
            call_count: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl DnsUpstreamPool for MockUpstream {
    async fn query(&self, _upstream_name: &str, _raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(self.response.clone())
    }
}

struct GatedUpstream {
    response: Vec<u8>,
    call_count: AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl DnsUpstreamPool for GatedUpstream {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        self.release.notified().await;
        Ok(self.response.clone())
    }
}

enum RefreshFenceLater {
    Response(Vec<u8>),
    Error,
}

struct RefreshFenceUpstream {
    initial: Vec<u8>,
    refreshed: Vec<u8>,
    later: RefreshFenceLater,
    call_count: AtomicUsize,
    refresh_entered: tokio::sync::Notify,
    refresh_release: tokio::sync::Semaphore,
}

#[async_trait]
impl DnsUpstreamPool for RefreshFenceUpstream {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        let call = self.call_count.fetch_add(1, Ordering::SeqCst);
        if call == 1 {
            self.refresh_entered.notify_one();
            self.refresh_release
                .acquire()
                .await
                .expect("refresh release")
                .forget();
        }
        match call {
            0 => Ok(self.initial.clone()),
            1 => Ok(self.refreshed.clone()),
            _ => match &self.later {
                RefreshFenceLater::Response(response) => Ok(response.clone()),
                RefreshFenceLater::Error => anyhow::bail!("foreground upstream down"),
            },
        }
    }
}
#[tokio::test]
async fn test_prefetch_warms_cache() {
    let response = make_a_response([1, 2, 3, 4], 300);
    let mock = Arc::new(GatedUpstream {
        response: response.clone(),
        call_count: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let cache = test_cache();
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        cache.clone(),
        test_router(),
    );

    let domains: Vec<String> = vec!["example.com".into()];
    forwarder.prefetch(&domains);
    mock.entered.notified().await;
    mock.release.notify_one();
    forwarder.prefetch_tasks.wait_empty().await;

    let query = make_a_query();
    let result = forwarder.resolve(&query).await.expect("resolve");
    assert_eq!(result, response);

    let calls = mock.call_count.load(Ordering::SeqCst);
    assert_eq!(calls, 1, "resolve must use the prefetched cache entry");
}

#[test]
fn test_parse_dns_question_a_record() {
    let query = build_dns_query("www.example.com", 1);
    let (domain, qtype) = parse_dns_question(&query).expect("parse");
    assert_eq!(domain, "www.example.com");
    assert_eq!(qtype, 1); // A
}

#[test]
fn test_parse_dns_question_aaaa_record() {
    let query = build_dns_query("ipv6.test.org", 28);
    let (domain, qtype) = parse_dns_question(&query).expect("parse");
    assert_eq!(domain, "ipv6.test.org");
    assert_eq!(qtype, 28); // AAAA
}

#[test]
fn test_parse_dns_question_truncated() {
    let short = vec![0u8; 10];
    assert!(parse_dns_question(&short).is_none());
}

#[test]
fn test_extract_min_ttl_single_answer() {
    let resp = make_a_response([8, 8, 8, 8], 300);
    let ttl = extract_min_ttl(&resp);
    assert_eq!(ttl, 300);
}

#[test]
fn test_extract_min_ttl_no_answers() {
    // Response with ANCOUNT=0
    let resp = vec![
        0x00, 0x01, // ID
        0x81, 0x83, // Flags: NXDOMAIN
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01,
        0x00, 0x01,
    ];
    let ttl = extract_min_ttl(&resp);
    assert_eq!(ttl, 60, "default TTL when no answers present");
}

#[test]
fn test_extract_min_ttl_short_response() {
    let short = vec![0u8; 5];
    assert_eq!(extract_min_ttl(&short), 60);
}

#[test]
fn test_build_and_parse_roundtrip() {
    let domains = vec![
        "google.com",
        "sub.domain.example.org",
        "localhost",
        "a.b.c.d.e.f.g.h.example.com",
    ];

    for domain in domains {
        for qtype in [1u16, 28u16, 5u16] {
            let query = build_dns_query(domain, qtype);
            let (parsed_domain, parsed_qtype) =
                parse_dns_question(&query).expect("roundtrip parse");
            assert_eq!(
                parsed_domain, domain,
                "domain mismatch for {} QTYPE={}",
                domain, qtype
            );
            assert_eq!(parsed_qtype, qtype, "qtype mismatch for {}", domain);
        }
    }
}

#[test]
fn test_rewrite_answer_ttls_overrides_wire() {
    let mut resp = make_a_response([1, 2, 3, 4], 30);
    assert_eq!(extract_min_ttl(&resp), 30);
    rewrite_answer_ttls(&mut resp, 600);
    assert_eq!(extract_min_ttl(&resp), 600);
}

#[test]
fn ttl_helpers_preserve_edns_opt_control_word() {
    let mut response = make_a_response([1, 2, 3, 4], 60_000);
    response[10..12].copy_from_slice(&1u16.to_be_bytes());
    let opt_offset = response.len();
    let control_word = [0x00, 0x00, 0x80, 0x00];
    response.extend_from_slice(&[
        0x00,
        0x00,
        0x29,
        0x04,
        0xd0,
        control_word[0],
        control_word[1],
        control_word[2],
        control_word[3],
        0x00,
        0x00,
    ]);

    assert_eq!(extract_min_ttl(&response), 60_000);
    rewrite_answer_ttls(&mut response, 600);
    assert_eq!(extract_min_ttl(&response), 600);
    assert_eq!(&response[opt_offset + 5..opt_offset + 9], &control_word);
}

#[test]
fn empty_response_preserves_exact_question_and_sanitizes_edns() {
    let mut query = build_dns_query("MiXeD.Example", 28);
    let question_end = query.len();
    query[3] |= 0x10;
    query[question_end - 2..question_end].copy_from_slice(&3u16.to_be_bytes());
    query[10..12].copy_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x00,
    ]);
    let context = crate::dns::query::QueryContext::parse(&query).expect("EDNS query");

    let response = make_empty_response(&query, &context);

    assert_eq!(&response[12..question_end], &query[12..question_end]);
    assert_eq!(u16::from_be_bytes([response[2], response[3]]), 0x8190);
    assert_eq!(&response[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        &response[question_end..],
        &[
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
        ]
    );
}
mod asis_transport;
mod cache_routing;
#[cfg(feature = "native-api")]
mod diagnostic;
mod family_and_negative;
mod rule_pipeline;
mod service_flush;
mod singleflight;
mod stale_refresh;
/// Mock upstream that always fails (serve-stale tests).
struct FailUpstream;

#[async_trait]
impl DnsUpstreamPool for FailUpstream {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("upstream down")
    }
}

/// Build an AAAA-record response for example.com with a given IPv6 and TTL.
fn make_aaaa_response(ip: [u8; 16], ttl: u32) -> Vec<u8> {
    let ttl_bytes = ttl.to_be_bytes();
    let mut v = vec![
        0x00,
        0x00, // ID
        0x81,
        0x80, // Flags: QR=1, RD=1, RA=1
        0x00,
        0x01, // QDCOUNT
        0x00,
        0x01, // ANCOUNT
        0x00,
        0x00, // NSCOUNT
        0x00,
        0x00, // ARCOUNT
        0x07,
        b'e',
        b'x',
        b'a',
        b'm',
        b'p',
        b'l',
        b'e',
        0x03,
        b'c',
        b'o',
        b'm',
        0x00,
        0x00,
        0x1c, // QTYPE AAAA
        0x00,
        0x01, // QCLASS IN
        0xc0,
        0x0c, // NAME pointer to offset 12
        0x00,
        0x1c, // TYPE AAAA
        0x00,
        0x01, // CLASS IN
        ttl_bytes[0],
        ttl_bytes[1],
        ttl_bytes[2],
        ttl_bytes[3], // TTL
        0x00,
        0x10, // RDLENGTH 16
    ];
    v.extend_from_slice(&ip);
    v
}

fn answer_count(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}

const TEST_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
#[test]
fn test_extract_answer_ips_a_record() {
    let resp = make_a_response([1, 2, 3, 4], 60);
    let ips = extract_answer_ips(&resp);
    assert_eq!(ips, vec![IpAddr::from([1, 2, 3, 4])]);
}
