use super::*;

#[test]
fn test_parse_resolver() {
    let r = BootstrapResolver::parse("udp://8.8.8.8:53").unwrap();
    assert_eq!(r.server, "8.8.8.8:53".parse().unwrap());
    assert!(!r.use_tcp);
    let r = BootstrapResolver::parse("tcp://1.1.1.1:53").unwrap();
    assert!(r.use_tcp);
    let r = BootstrapResolver::parse("9.9.9.9:53").unwrap();
    assert!(!r.use_tcp);
    assert!(BootstrapResolver::parse("").is_none());
    assert!(BootstrapResolver::parse("not-an-addr").is_none());
}

#[test]
fn test_build_and_parse_roundtrip() {
    let query = build_query("example.com", 1);
    let mut resp = query.clone();
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[6] = 0;
    resp[7] = 1; // ancount = 1
    resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer
    resp.extend_from_slice(&1u16.to_be_bytes()); // A
    resp.extend_from_slice(&1u16.to_be_bytes()); // IN
    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
    resp.extend_from_slice(&4u16.to_be_bytes()); // rdlen
    resp.extend_from_slice(&[93, 184, 216, 34]);
    let ips = parse_answers(&resp, 1).unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
}

#[tokio::test]
async fn test_resolve_literal_ip_skips_lookup() {
    let ips = resolve("1.2.3.4").await.unwrap();
    assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
}

fn qtype(query: &[u8]) -> u16 {
    u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]])
}

/// A reply to `query` answering with the entries of `ips` in the queried family.
fn addr_response(query: &[u8], ips: &[IpAddr]) -> Vec<u8> {
    let qtype = qtype(query);
    let mut resp = query.to_vec();
    resp[2] = 0x81;
    resp[3] = 0x80;
    let mut count = 0u16;
    for ip in ips {
        let rdata = match (qtype, ip) {
            (1, IpAddr::V4(ip)) => ip.octets().to_vec(),
            (28, IpAddr::V6(ip)) => ip.octets().to_vec(),
            _ => continue,
        };
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&qtype.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);
        count += 1;
    }
    resp[6..8].copy_from_slice(&count.to_be_bytes());
    resp
}

/// Loopback UDP DNS stub sending every datagram of `replies(query)` per query.
async fn spawn_udp_stub(replies: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static) -> SocketAddr {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            for reply in replies(&buf[..n]) {
                server.send_to(&reply, peer).await.unwrap();
            }
        }
    });
    addr
}

/// End-to-end: a stub UDP DNS server on loopback answering A records,
/// installed as the global bootstrap resolver.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn test_resolve_via_bootstrap_udp() {
    let _lock = GLOBAL_TEST_LOCK.lock().unwrap();
    let a = IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7));
    let server_addr = spawn_udp_stub(move |query| vec![addr_response(query, &[a])]).await;

    set_global(BootstrapResolver::parse(&format!("udp://{}", server_addr)));
    let ips = resolve("node.example.com").await.unwrap();
    set_global(None);
    assert_eq!(ips, vec![a]);
}

#[tokio::test]
async fn silent_aaaa_keeps_a_answer_within_family_budget() {
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));
    let server = spawn_udp_stub(move |query| match qtype(query) {
        1 => vec![addr_response(query, &[a])],
        _ => Vec::new(),
    })
    .await;
    let resolver = BootstrapResolver::parse(&format!("udp://{server}"));

    let ips = tokio::time::timeout(
        QUERY_TIMEOUT + Duration::from_secs(2),
        resolve_with(resolver, "a-only.invalid"),
    )
    .await
    .expect("resolution finishes within one family budget")
    .unwrap();
    assert_eq!(ips, vec![a]);
}

#[tokio::test]
async fn truncated_udp_answer_retries_over_tcp() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    // UDP only returns an empty truncated reply; the answer exists only over TCP.
    let server = spawn_udp_stub(|query| {
        let mut truncated = addr_response(query, &[]);
        truncated[2] |= 0x02;
        vec![truncated]
    })
    .await;
    let tcp = tokio::net::TcpListener::bind(server).await.unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            tokio::spawn(async move {
                let mut query = vec![0; stream.read_u16().await.unwrap() as usize];
                stream.read_exact(&mut query).await.unwrap();
                let response = addr_response(&query, &[a]);
                stream.write_u16(response.len() as u16).await.unwrap();
                stream.write_all(&response).await.unwrap();
            });
        }
    });

    let resolver = BootstrapResolver::parse(&format!("udp://{server}")).unwrap();
    let ips = resolver.query("many-records.invalid").await.unwrap();
    assert_eq!(ips, vec![a]);
}

/// Replies to `query` that must be rejected: a wrong ID, and the right ID
/// for a different name.
fn mismatched_replies(query: &[u8], ip: IpAddr) -> Vec<Vec<u8>> {
    let mut wrong_id = addr_response(query, &[ip]);
    wrong_id[0] ^= 0xff;
    let mut wrong_name = addr_response(query, &[ip]);
    wrong_name[13] ^= 0x01;
    vec![wrong_id, wrong_name]
}

#[tokio::test]
async fn udp_exchange_accepts_only_the_reply_matching_the_query() {
    let good = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let spoofed = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 66));
    let server = spawn_udp_stub(move |query| {
        let mut replies = mismatched_replies(query, spoofed);
        let mut reply = addr_response(query, &[good]);
        reply[12..query.len() - 4].make_ascii_uppercase();
        replies.push(reply);
        replies
    })
    .await;
    let resolver = BootstrapResolver::parse(&format!("udp://{server}")).unwrap();
    assert_eq!(
        resolver.query("node.example.com").await.unwrap(),
        vec![good]
    );

    let spoof_only = spawn_udp_stub(move |query| mismatched_replies(query, spoofed)).await;
    let resolver = BootstrapResolver::parse(&format!("udp://{spoof_only}")).unwrap();
    let accepted = tokio::time::timeout(
        Duration::from_millis(300),
        resolver.query_raw("node.example.com", 1),
    )
    .await;
    assert!(
        accepted.is_err(),
        "a reply that does not match the query must not be accepted"
    );
}

/// Build a DNS response carrying one HTTPS (65) answer for the query's
/// question, with the given priority and `ech` SvcParam (or none).
fn make_https_response(query: &[u8], priority: u16, ech: Option<&[u8]>, ttl: u32) -> Vec<u8> {
    let mut resp = query.to_vec();
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[6] = 0;
    resp[7] = 1; // ancount = 1
    resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer to question
    resp.extend_from_slice(&65u16.to_be_bytes()); // TYPE HTTPS
    resp.extend_from_slice(&1u16.to_be_bytes()); // IN
    resp.extend_from_slice(&ttl.to_be_bytes());
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&priority.to_be_bytes());
    rdata.push(0); // target name = root
    if let Some(ech) = ech {
        rdata.extend_from_slice(&5u16.to_be_bytes()); // SvcParam key ech
        rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
        rdata.extend_from_slice(ech);
    }
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);
    resp
}

#[test]
fn test_parse_https_rr_ech() {
    let query = build_query("example.com", 65);
    let ech = b"\x00\x01fake-ech-config";
    // ServiceMode (priority >= 1) with an ech param.
    let resp = make_https_response(&query, 1, Some(ech), 300);
    assert_eq!(
        parse_https_rr_ech(&resp),
        Some((ech.to_vec(), 300)),
        "ServiceMode HTTPS RR with ech param"
    );

    // AliasMode (priority 0) carries no SvcParams — skipped even when
    // bytes shaped like params follow (they are part of the TargetName).
    let resp = make_https_response(&query, 0, Some(ech), 300);
    assert_eq!(parse_https_rr_ech(&resp), None);

    // ServiceMode without an ech param.
    let resp = make_https_response(&query, 1, None, 300);
    assert_eq!(parse_https_rr_ech(&resp), None);
}

/// End-to-end: stub UDP DNS server answering HTTPS records with an ech
/// SvcParam, installed as the global bootstrap resolver.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn test_query_ech_config_via_bootstrap_udp() {
    let _lock = GLOBAL_TEST_LOCK.lock().unwrap();
    let ech = b"\x00\x02real-ech-bytes";
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        let resp = make_https_response(&buf[..n], 1, Some(ech), 120);
        server.send_to(&resp, peer).await.unwrap();
    });

    set_global(BootstrapResolver::parse(&format!("udp://{}", server_addr)));
    let got = query_ech_config("node.example.com").await.unwrap();
    set_global(None);
    assert_eq!(got, Some((ech.to_vec(), 120)));

    // IP literals never hit the network.
    assert_eq!(query_ech_config("1.2.3.4").await.unwrap(), None);
}

#[test]
fn system_hosts_matches_aliases_and_address_families() {
    let hosts = "# 192.0.2.1 hidden\n\
                 127.0.0.1 localhost alias # ignored\n\
                 ::1 LOCALHOST ip6-localhost\n\
                 127.0.0.1 localhost\n\
                 invalid localhost\n\
                 192.0.2.2 localhost.example\n";
    assert_eq!(
        hosts_addresses(hosts, "LocalHost."),
        vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "::1".parse::<IpAddr>().unwrap()
        ]
    );
    assert_eq!(
        hosts_addresses(hosts, "alias"),
        vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
    );
    assert!(hosts_addresses(hosts, "ignored").is_empty());
    assert!(hosts_addresses(hosts, "hidden").is_empty());
}
