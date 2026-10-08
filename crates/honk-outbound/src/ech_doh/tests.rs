use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

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

fn test_source(qname: &str) -> EchDohSource {
    let url = "https://127.0.0.1:1/dns-query".to_string();
    let endpoint = DohEndpoint::parse(&url).unwrap();
    EchDohSource {
        qname: qname.to_string(),
        url,
        endpoint,
    }
}

#[test]
fn parse_accepts_plus_and_space_separators() {
    let EchFetchSource::Doh(source) =
        parse_ech_source("cloudflare-ech.com+https://223.5.5.5/dns-query").unwrap()
    else {
        panic!("expected Doh");
    };
    assert_eq!(source.qname, "cloudflare-ech.com");
    assert_eq!(source.url, "https://223.5.5.5/dns-query");

    // A literal `+` decodes to a space in query strings; both spellings
    // must yield the same source.
    let EchFetchSource::Doh(spaced) =
        parse_ech_source("cloudflare-ech.com https://223.5.5.5/dns-query").unwrap()
    else {
        panic!("expected Doh");
    };
    assert_eq!(spaced, source);
}

#[test]
fn parse_bare_qname_uses_bootstrap_dns() {
    let EchFetchSource::BootstrapDns(qname) = parse_ech_source("cloudflare-ech.com").unwrap()
    else {
        panic!("expected BootstrapDns");
    };
    assert_eq!(qname, "cloudflare-ech.com");
}

#[test]
fn parse_normalizes_qname_and_keeps_url_parts() {
    let EchFetchSource::Doh(source) =
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

static FETCH_CALLS_COLD: AtomicUsize = AtomicUsize::new(0);
static FETCH_CALLS_REFRESH: AtomicUsize = AtomicUsize::new(0);
static FETCH_CALLS_FAIL: AtomicUsize = AtomicUsize::new(0);

fn stub_fetch_cold(_source: &EchDohSource) -> super::EchFetchFuture {
    Box::pin(async move {
        let n = FETCH_CALLS_COLD.fetch_add(1, Ordering::SeqCst);
        Ok((vec![n as u8; 8], 60))
    })
}

fn stub_fetch_refresh(_source: &EchDohSource) -> super::EchFetchFuture {
    Box::pin(async move {
        FETCH_CALLS_REFRESH.fetch_add(1, Ordering::SeqCst);
        Ok((vec![1; 8], 60))
    })
}

fn stub_failing(_source: &EchDohSource) -> super::EchFetchFuture {
    Box::pin(async move {
        FETCH_CALLS_FAIL.fetch_add(1, Ordering::SeqCst);
        Err(anyhow::anyhow!("boom"))
    })
}

async fn wait_for(mut condition: impl FnMut() -> bool, what: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

#[tokio::test]
async fn cold_path_waits_for_first_fetch() {
    FETCH_CALLS_COLD.store(0, Ordering::SeqCst);
    let source = test_source("cold-wait.invalid");
    // No refresher running: the cold path must fetch inline and return it.
    let config = ech_doh_config_with(&source, stub_fetch_cold).await.unwrap();
    assert_eq!(*config, vec![0; 8]);
    assert_eq!(FETCH_CALLS_COLD.load(Ordering::SeqCst), 1);
    // Second call hits the cache without another fetch.
    let cached = ech_doh_config_with(&source, stub_fetch_cold).await.unwrap();
    assert!(Arc::ptr_eq(&config, &cached));
    assert_eq!(FETCH_CALLS_COLD.load(Ordering::SeqCst), 1);
    REFRESH_TASKS.remove(&source);
    ECH_DOH_CACHE.remove(&source);
}

#[tokio::test]
async fn cold_path_fails_open_and_schedules_background_retry() {
    let source = test_source("cold-fail.invalid");
    assert!(ech_doh_config_with(&source, stub_failing).await.is_none());
    // The refresher is scheduled to keep retrying; this dial fails open.
    assert!(REFRESH_TASKS.contains_key(&source));
    REFRESH_TASKS.remove(&source);
    ECH_DOH_CACHE.remove(&source);
}

#[tokio::test]
async fn refresh_loop_renews_config() {
    let source = test_source("refresh-renew.invalid");
    let slot = Arc::new(EchDohSlot::new());
    *slot.config.write() = Some(Arc::new(vec![9; 4]));
    let refresher = tokio::spawn(refresh_loop(
        source.clone(),
        slot.clone(),
        stub_fetch_refresh,
        Duration::from_millis(50),
        Duration::from_millis(20),
        Duration::from_secs(60),
    ));
    // One refresh cycle replaces the stale config.
    wait_for(
        || {
            slot.config
                .read()
                .as_ref()
                .is_some_and(|c| **c != vec![9; 4])
        },
        "periodic refresh",
    )
    .await;
    assert_eq!(**slot.config.read().as_ref().unwrap(), vec![1; 8]);
    refresher.abort();
    REFRESH_TASKS.remove(&source);
    ECH_DOH_CACHE.remove(&source);
}

#[tokio::test]
async fn refresh_loop_keeps_stale_config_on_failure() {
    FETCH_CALLS_FAIL.store(0, Ordering::SeqCst);
    let source = test_source("refresh-fail.invalid");
    let slot = Arc::new(EchDohSlot::new());
    *slot.config.write() = Some(Arc::new(vec![7; 4]));
    let refresher = tokio::spawn(refresh_loop(
        source.clone(),
        slot.clone(),
        stub_failing,
        Duration::from_millis(20),
        Duration::from_millis(20),
        Duration::from_secs(60),
    ));
    // Wait until a refresh was actually attempted (and failed).
    wait_for(
        || FETCH_CALLS_FAIL.load(Ordering::SeqCst) >= 1,
        "failed refresh attempt",
    )
    .await;
    let cached = slot.config.read().clone().unwrap();
    assert_eq!(
        *cached,
        vec![7; 4],
        "failed refresh must keep the old config"
    );
    refresher.abort();
    REFRESH_TASKS.remove(&source);
    ECH_DOH_CACHE.remove(&source);
}

#[tokio::test]
async fn published_config_reaches_later_reads() {
    // `start_session` (QUIC) and `connect` (TLS) read the cache
    // per-connection; a published config must be visible immediately.
    let source = test_source("publish.invalid");
    let slot = Arc::new(EchDohSlot::new());
    *slot.config.write() = Some(Arc::new(vec![1; 4]));
    ECH_DOH_CACHE.insert(source.clone(), slot);
    assert_eq!(*cached_ech_doh_config(&source).unwrap(), vec![1; 4]);
    publish_config(&source, vec![2; 4]);
    assert_eq!(*cached_ech_doh_config(&source).unwrap(), vec![2; 4]);
    ECH_DOH_CACHE.remove(&source);
}

#[tokio::test]
async fn refresh_loop_stops_when_idle() {
    let source = test_source("idle-reap.invalid");
    let slot = Arc::new(EchDohSlot::new());
    *slot.last_used.lock() = Instant::now() - ECH_DOH_IDLE_TIMEOUT - Duration::from_secs(1);
    REFRESH_TASKS.insert(source.clone(), ());
    ECH_DOH_CACHE.insert(source.clone(), slot.clone());
    let refresher = tokio::spawn(refresh_loop(
        source.clone(),
        slot,
        stub_fetch_refresh,
        Duration::from_millis(20),
        Duration::from_millis(20),
        ECH_DOH_IDLE_TIMEOUT,
    ));
    wait_for(|| !REFRESH_TASKS.contains_key(&source), "idle reaper").await;
    assert!(!ECH_DOH_CACHE.contains_key(&source));
    let _ = refresher.await;
}
