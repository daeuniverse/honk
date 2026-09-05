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
fn test_parse_dns_question_single_label() {
    let query = build_dns_query("localhost", 1);
    let (domain, qtype) = parse_dns_question(&query).expect("parse");
    assert_eq!(domain, "localhost");
    assert_eq!(qtype, 1);
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
fn test_extract_min_ttl_keeps_zero_and_normalizes_high_bit() {
    assert_eq!(extract_min_ttl(&make_a_response([8, 8, 8, 8], 0)), 0);

    assert_eq!(extract_min_ttl(&make_a_response([8, 8, 8, 8], 0x8000_0001)), 0);
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
fn test_effective_cache_ttl_override() {
    assert_eq!(effective_cache_ttl(600, 30), 600);
    assert_eq!(effective_cache_ttl(0, 30), 30);
    assert_eq!(effective_cache_ttl(0, 0), 1);
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
        0x00, 0x00, 0x29, 0x04, 0xd0, control_word[0], control_word[1], control_word[2],
        control_word[3], 0x00, 0x00,
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
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04, 0x00, 0x0c,
        0x00, 0x00,
    ]);
    let context = crate::dns::query::QueryContext::parse(&query).expect("EDNS query");

    let response = make_empty_response(&query, &context);

    assert_eq!(&response[12..question_end], &query[12..question_end]);
    assert_eq!(u16::from_be_bytes([response[2], response[3]]), 0x8190);
    assert_eq!(&response[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        &response[question_end..],
        &[0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00]
    );
}
