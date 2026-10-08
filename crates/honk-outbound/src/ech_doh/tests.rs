use super::*;

/// Real DoH response captured from `https://223.5.5.5/dns-query?dns=...`
/// for `cloudflare-ech.com` type 65 (195 bytes).
const DOH_RESPONSE: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x63, 0x6c, 0x6f,
    0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x65, 0x63, 0x68, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    0x00, 0x41, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x88,
    0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x06, 0x02, 0x68, 0x33, 0x02, 0x68, 0x32, 0x00, 0x04, 0x00,
    0x08, 0x68, 0x12, 0x0a, 0x76, 0x68, 0x12, 0x0b, 0x76, 0x00, 0x05, 0x00, 0x47, 0x00, 0x45, 0xfe,
    0x0d, 0x00, 0x41, 0x11, 0x00, 0x20, 0x00, 0x20, 0xef, 0x4a, 0x1c, 0x15, 0x07, 0xee, 0x51, 0x9b,
    0xb7, 0x0e, 0xa2, 0xe7, 0x1a, 0x49, 0x76, 0xb7, 0xe0, 0xb8, 0xb0, 0x83, 0x21, 0x83, 0x11, 0xd0,
    0x15, 0x46, 0x79, 0xe5, 0xfc, 0x82, 0xd1, 0x10, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x12,
    0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x65, 0x63, 0x68, 0x2e, 0x63,
    0x6f, 0x6d, 0x00, 0x00, 0x00, 0x06, 0x00, 0x20, 0x26, 0x06, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x68, 0x12, 0x0a, 0x76, 0x26, 0x06, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x68, 0x12, 0x0b, 0x76, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
];

/// The `ech` SvcParam value (key 5) inside `DOH_RESPONSE`.
const EXPECTED_ECH: &[u8] = &[
    0x00, 0x45, 0xfe, 0x0d, 0x00, 0x41, 0x11, 0x00, 0x20, 0x00, 0x20, 0xef, 0x4a, 0x1c, 0x15, 0x07,
    0xee, 0x51, 0x9b, 0xb7, 0x0e, 0xa2, 0xe7, 0x1a, 0x49, 0x76, 0xb7, 0xe0, 0xb8, 0xb0, 0x83, 0x21,
    0x83, 0x11, 0xd0, 0x15, 0x46, 0x79, 0xe5, 0xfc, 0x82, 0xd1, 0x10, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x65, 0x63,
    0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
];

fn test_doh_source(qname: &str) -> EchSource {
    let url = "https://127.0.0.1:1/dns-query".to_string();
    let endpoint = DohEndpoint::parse(&url).unwrap();
    EchSource::Doh(EchDohSource {
        qname: qname.to_string(),
        url,
        endpoint,
    })
}

fn test_discover_source(domain: &str) -> EchSource {
    EchSource::Discover(domain.to_string())
}

#[test]
fn parse_accepts_plus_and_space_separators() {
    let EchSource::Doh(source) =
        parse_ech_source("cloudflare-ech.com+https://223.5.5.5/dns-query").unwrap()
    else {
        panic!("expected Doh");
    };
    assert_eq!(source.qname, "cloudflare-ech.com");
    assert_eq!(source.url, "https://223.5.5.5/dns-query");

    // A literal `+` decodes to a space in query strings; both spellings
    // must yield the same source.
    let EchSource::Doh(spaced) =
        parse_ech_source("cloudflare-ech.com https://223.5.5.5/dns-query").unwrap()
    else {
        panic!("expected Doh");
    };
    assert_eq!(spaced, source);
}

#[test]
fn parse_bare_qname_uses_bootstrap_dns() {
    let EchSource::Discover(qname) = parse_ech_source("cloudflare-ech.com").unwrap() else {
        panic!("expected Discover");
    };
    assert_eq!(qname, "cloudflare-ech.com");
}

#[test]
fn parse_normalizes_qname_and_keeps_url_parts() {
    let EchSource::Doh(source) =
        parse_ech_source("  Example.COM.+https://doh.example:8443/dns-query?dns=abc ").unwrap()
    else {
        panic!("expected Doh");
    };
    assert_eq!(source.qname, "example.com");
    assert_eq!(source.url, "https://doh.example:8443/dns-query?dns=abc");
}

#[test]
fn parse_rejects_malformed_sources() {
    for raw in [
        "",
        "1",
        "true",
        "nodot",
        "+https://223.5.5.5/dns-query",
        " +https://223.5.5.5/dns-query",
        "1.2.3.4+https://223.5.5.5/dns-query",
        "cloudflare-ech.com+http://223.5.5.5/dns-query",
        "cloudflare-ech.com+https://",
        "cloudflare-ech.com+notaurl",
        "cloudflare-ech.com+",
        "bad!name.com+https://223.5.5.5/dns-query",
        ".+https://223.5.5.5/dns-query",
    ] {
        assert!(parse_ech_source(raw).is_err(), "should reject {raw:?}");
    }
}

#[test]
fn endpoint_parse_and_authority() {
    let endpoint = DohEndpoint::parse("https://223.5.5.5/dns-query").unwrap();
    assert_eq!(endpoint.host, "223.5.5.5");
    assert_eq!(endpoint.port, 443);
    assert_eq!(endpoint.path, "/dns-query");
    assert_eq!(endpoint.authority(), "223.5.5.5");

    let endpoint = DohEndpoint::parse("https://example.com").unwrap();
    assert_eq!(endpoint.path, "/dns-query");

    let endpoint = DohEndpoint::parse("https://[::1]:8443/dns-query?dns=abc").unwrap();
    assert_eq!(endpoint.host, "::1");
    assert_eq!(endpoint.port, 8443);
    assert_eq!(endpoint.path, "/dns-query?dns=abc");
    assert_eq!(endpoint.authority(), "[::1]:8443");

    let endpoint = DohEndpoint::parse("https://example.com:8443/").unwrap();
    assert_eq!(endpoint.authority(), "example.com:8443");
}

#[test]
fn dial_addr_always_carries_an_explicit_port() {
    // `connect_marked` requires `host:port`; omitting 443 used to make every
    // default-port fetch fail, and `[v6]` without a port split inside the
    // address.
    let endpoint = DohEndpoint::parse("https://223.5.5.5/dns-query").unwrap();
    assert_eq!(endpoint.dial_addr(), "223.5.5.5:443");

    let endpoint = DohEndpoint::parse("https://[2001:db8::1]/dns-query").unwrap();
    assert_eq!(endpoint.dial_addr(), "[2001:db8::1]:443");

    let endpoint = DohEndpoint::parse("https://example.com:8443/dns-query").unwrap();
    assert_eq!(endpoint.dial_addr(), "example.com:8443");

    let endpoint = DohEndpoint::parse("https://[::1]:8443/dns-query").unwrap();
    assert_eq!(endpoint.dial_addr(), "[::1]:8443");
}

#[tokio::test]
async fn dial_addr_connects_through_connect_outbound() {
    // End-to-end through the real dial path: the formatted address must be
    // accepted by `connect_outbound` (bypass-marked TCP).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = DohEndpoint::parse(&format!("https://127.0.0.1:{port}/dns-query")).unwrap();
    let dial_addr = endpoint.dial_addr();
    let (accepted, connected) = tokio::join!(
        listener.accept(),
        crate::util::connect_outbound(&dial_addr, Duration::from_secs(5)),
    );
    accepted.unwrap();
    connected.unwrap();
}

#[test]
fn https_rr_query_wire_format() {
    let query = crate::bootstrap::build_query("cloudflare-ech.com", crate::bootstrap::QTYPE_HTTPS);
    // id(2) flags(2) qdcount(2) an/ns/ar(6) qname qtype(2) qclass(2)
    assert_eq!(
        &query[2..12],
        &[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        &query[12..],
        b"\x0ecloudflare-ech\x03com\x00\x00\x41\x00\x01".as_slice()
    );
}

#[test]
fn doh_response_is_matched_to_the_query() {
    let query = crate::bootstrap::build_query("cloudflare-ech.com", crate::bootstrap::QTYPE_HTTPS);
    // The captured response has a fixed id; craft a query with that id.
    let mut query = query;
    query[0] = 0x12;
    query[1] = 0x34;
    assert!(crate::bootstrap::answers_query(&query, DOH_RESPONSE));
    let mut wrong_id = DOH_RESPONSE.to_vec();
    wrong_id[0] ^= 0xff;
    assert!(!crate::bootstrap::answers_query(&query, &wrong_id));
}

#[tokio::test]
async fn doh_post_round_trips_dns_response() {
    let (client_io, server_io) = tokio::io::duplex(65536);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(
            request.headers().get("content-type").unwrap(),
            "application/dns-message"
        );
        let mut body = request.into_body();
        let mut query = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            query.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(chunk.len());
        }
        assert_eq!(
            &query[2..12],
            &[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            &query[12..],
            b"\x0ecloudflare-ech\x03com\x00\x00\x41\x00\x01".as_slice()
        );
        // Echo the query's id in the response so the client's match check passes.
        let mut response_body = DOH_RESPONSE.to_vec();
        response_body[0] = query[0];
        response_body[1] = query[1];
        let response = http::Response::builder().status(200).body(()).unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(Bytes::from(response_body), true).unwrap();
        // Keep driving the connection so the queued DATA reaches the client.
        while connection.accept().await.is_some() {}
    });

    let query = crate::bootstrap::build_query("cloudflare-ech.com", crate::bootstrap::QTYPE_HTTPS);
    let body = doh_h2_post(client_io, "example.com", "/dns-query", &query)
        .await
        .unwrap();
    let mut expected = DOH_RESPONSE.to_vec();
    expected[0] = query[0];
    expected[1] = query[1];
    assert_eq!(body, expected);
    let (ech, ttl) = crate::bootstrap::parse_https_rr_ech(&body).unwrap();
    assert_eq!(ech, EXPECTED_ECH);
    assert_eq!(ttl, 1);
    server.abort();
}

#[test]
fn cache_miss_returns_none() {
    let source = test_discover_source("cache-miss.invalid");
    assert!(cached_ech_config(&source).is_none());
}

#[test]
fn published_config_is_visible_to_later_reads() {
    // QUIC `start_session` and TLS `connect` read the cache per-connection;
    // a published config (e.g. ECH_REJECTED retry configs) must be visible
    // immediately.
    let source = test_doh_source("publish.invalid");
    publish_ech_config(&source, vec![2; 4]);
    let cached = cached_ech_config(&source).unwrap();
    assert_eq!(&*cached, &[2; 4]);
    ECH_CACHE.lock().unwrap().remove(&source);
}

#[test]
fn cache_entry_expires() {
    let source = test_discover_source("cache-expire.invalid");
    ECH_CACHE.lock().unwrap().insert(
        source.clone(),
        EchCacheEntry {
            config: Some(vec![1; 4].into()),
            expires: Instant::now() - Duration::from_secs(1),
        },
    );
    assert!(cached_ech_config(&source).is_none());
    ECH_CACHE.lock().unwrap().remove(&source);
}

#[test]
fn negative_entry_caches_the_absence() {
    let source = test_discover_source("cache-negative.invalid");
    cache_put(&source, None, 60);
    // A negative entry is a hit (Some(None)): `cached_ech_config` flattens
    // it to `None`, but the entry exists so no refetch is triggered.
    assert!(cache_get(&source).is_some());
    assert!(cached_ech_config(&source).is_none());
    ECH_CACHE.lock().unwrap().remove(&source);
}

#[test]
fn discover_and_doh_sources_do_not_share_entries() {
    let discover = test_discover_source("shared.invalid");
    let doh = test_doh_source("shared.invalid");
    assert_ne!(discover, doh);
    publish_ech_config(&discover, vec![1; 4]);
    assert!(cached_ech_config(&doh).is_none());
    ECH_CACHE.lock().unwrap().remove(&discover);
}
