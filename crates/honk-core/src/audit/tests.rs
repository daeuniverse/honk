use super::*;
use std::time::Duration;

mod metadata;

fn identity() -> Identity {
    Identity {
        hostname: "router01".into(),
        app_name: "honk-audit".into(),
    }
}

pub(crate) fn test_pending_event(mut pending: DnsAuditQuery) -> serde_json::Value {
    let input = pending.entry.take().unwrap();
    pending.permit.take();
    let event = encode(&input, "instance:1").unwrap();
    decode_frame(&super::frame(&event, input.completed, &identity(), true).unwrap())
}

fn frame(
    value: &serde_json::Value,
    time: SystemTime,
    identity: &Identity,
) -> std::io::Result<Vec<u8>> {
    super::frame(value, time, identity, true)
}

fn query() -> Vec<u8> {
    crate::dns::forwarder::build_dns_query("audit.example", 1)
}

fn entry(response: Vec<u8>) -> Entry {
    Entry {
        started: SystemTime::UNIX_EPOCH,
        completed: SystemTime::UNIX_EPOCH + Duration::from_millis(10),
        duration: Duration::from_millis(10),
        upstream: None,
        source: "[::ffff:192.0.2.8]:53000".parse().unwrap(),
        ingress: IngressProfile::Tcp,
        query: query().into(),
        response: Some(response.into()),
        _query_memory: None,
        _response_memory: None,
    }
}

struct SocketConnector(SocketAddr);

impl transport::Connector for SocketConnector {
    type Stream = tokio::net::TcpStream;
    async fn connect(&mut self) -> std::io::Result<Self::Stream> {
        tokio::net::TcpStream::connect(self.0).await
    }
}

pub(crate) struct Receiver {
    listener: tokio::net::TcpListener,
    stream: Option<tokio::net::TcpStream>,
}

pub(crate) async fn receiver() -> (DnsAudit, DnsAuditWorker, Receiver) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (audit, worker) = DnsAuditWorker::with_connector(
        SocketConnector(listener.local_addr().unwrap()),
        identity(),
        true,
    );
    (
        audit,
        worker,
        Receiver {
            listener,
            stream: None,
        },
    )
}

pub(super) fn decode_message(message: &[u8]) -> serde_json::Value {
    let text = std::str::from_utf8(message).unwrap();
    assert!(text.starts_with("<134>1 "));
    let body = text.splitn(8, ' ').nth(7).unwrap();
    serde_json::from_str(body.strip_prefix("@cee: ").unwrap_or(body)).unwrap()
}

pub(super) fn decode_frame(bytes: &[u8]) -> serde_json::Value {
    let split = bytes.iter().position(|byte| *byte == b' ').unwrap();
    let length: usize = std::str::from_utf8(&bytes[..split])
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(bytes.len() - split - 1, length);
    decode_message(&bytes[split + 1..])
}

pub(super) async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
) -> serde_json::Value {
    use tokio::io::AsyncReadExt;
    let mut prefix = Vec::new();
    loop {
        let byte = stream.read_u8().await.unwrap();
        if byte == b' ' {
            break;
        }
        assert!(byte.is_ascii_digit());
        prefix.push(byte);
        assert!(prefix.len() <= 8);
    }
    let length: usize = std::str::from_utf8(&prefix).unwrap().parse().unwrap();
    assert!(length <= MAX_EVENT_BYTES);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await.unwrap();
    decode_message(&bytes)
}

pub(crate) async fn receive(receiver: &mut Receiver) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        if receiver.stream.is_none() {
            receiver.stream = Some(receiver.listener.accept().await.unwrap().0);
        }
        read_frame(receiver.stream.as_mut().unwrap()).await
    })
    .await
    .unwrap()
}

#[test]
fn default_is_inert_and_creates_no_runtime() {
    let (audit, worker) = DnsAuditWorker::start(&Default::default()).unwrap();
    assert!(worker.is_none());
    assert!(
        audit
            .begin(
                &query(),
                IngressProfile::Tcp,
                "127.0.0.1:1".parse().unwrap()
            )
            .is_none()
    );
}

#[test]
fn fixed_json_frames_preserve_events_with_and_without_cee() {
    for (cee, header) in [
        (
            false,
            "<134>1 1970-01-01T00:00:00.010000Z router01 honk-audit - dns.query - ",
        ),
        (
            true,
            "<134>1 1970-01-01T00:00:00.010000Z router01 honk-audit - dns.query - @cee: ",
        ),
    ] {
        let mut positive = query();
        positive[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        positive[6..8].copy_from_slice(&1u16.to_be_bytes());
        positive.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 8]);
        for response in [
            Some(crate::dns::response::build_dns_refused(&query())),
            Some(positive),
            None,
        ] {
            let mut input = entry(Vec::new());
            input.response = response.map(Vec::into_boxed_slice);
            let value = encode(&input, "instance:1").unwrap();
            let mut message = header.as_bytes().to_vec();
            serde_json::to_writer(&mut message, &value).unwrap();
            let mut expected = format!("{} ", message.len()).into_bytes();
            expected.extend(message);
            let actual = super::frame(&value, input.completed, &identity(), cee).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(decode_frame(&actual), value);
        }
    }
}

#[test]
fn response_projection_keeps_rcode_source_and_actual_answers() {
    let wire = crate::dns::response::build_dns_refused(&query());
    let value = encode(&entry(wire), "instance:1").unwrap();
    assert_eq!(value["domain"], "audit.example.");
    assert_eq!(value["client_ip"], "192.0.2.8");
    assert_eq!(value["client_port"], 53000);
    assert_eq!(value["query_time"], "1970-01-01T00:00:00.000000Z");
    assert_eq!(value["rcode"], "REFUSED");
    assert_eq!(value["answers"], json!([]));
    assert_eq!(value["answer_ips"], json!([]));
    assert_eq!(value["answer_cnames"], json!([]));
    assert_eq!(value["answer_types"], json!([]));
    let mut truncated = query();
    truncated[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
    let mut truncated = entry(truncated);
    truncated.ingress = IngressProfile::Udp {
        advertised_size: 512,
    };
    let value = encode(&truncated, "instance:2").unwrap();
    assert_eq!(value["response_truncated"], true);
}

#[test]
fn readable_message_identifies_responses_and_cancellation() {
    let mut input = entry(crate::dns::response::build_dns_refused(&query()));
    let value = encode(&input, "instance:1").unwrap();
    assert_eq!(
        value["message"],
        "DNS 192.0.2.8 audit.example. A IN: REFUSED answers=0"
    );
    assert_eq!(value["result"], "response");
    assert_eq!(value["rcode"], "REFUSED");
    input.response = None;
    input.source = "[2001:db8::8]:53000".parse().unwrap();
    let value = encode(&input, "instance:2").unwrap();
    assert_eq!(
        value["message"],
        "DNS 2001:db8::8 audit.example. A IN: cancelled answers=0"
    );
    assert_eq!(value["result"], "cancelled");
    assert!(value["rcode"].is_null());
    assert_eq!(value["answers"], json!([]));
}

#[test]
fn queue_reservations_bound_inflight_wire_memory() {
    let (sender, mut receiver) = mpsc::channel(QUEUE_LEN);
    let audit = DnsAudit {
        sender: Some(sender),
        admission: Arc::default(),
    };
    let source = "192.0.2.1:53".parse().unwrap();
    let reservations: Vec<_> = (0..QUEUE_LEN)
        .map(|_| audit.begin(&query(), IngressProfile::Tcp, source).unwrap())
        .collect();
    assert!(audit.begin(&query(), IngressProfile::Tcp, source).is_none());
    assert_eq!(audit.admission.counters.dropped.load(Ordering::Relaxed), 1);
    drop(reservations);
    for _ in 0..QUEUE_LEN {
        let entry = receiver.try_recv().unwrap();
        assert!(entry.response.is_none());
    }
    assert!(receiver.try_recv().is_err());
    receiver.close();
    assert!(audit.begin(&query(), IngressProfile::Tcp, source).is_none());
}

#[test]
fn raw_byte_budget_rejects_new_events_and_releases_all_permits() {
    let (sender, mut receiver) = mpsc::channel(QUEUE_LEN);
    let audit = DnsAudit {
        sender: Some(sender),
        admission: Arc::default(),
    };
    let large = vec![0; WIRE_LIMIT];
    let mut held = Vec::new();
    while let Some(query) =
        audit.begin(&large, IngressProfile::Tcp, "192.0.2.1:53".parse().unwrap())
    {
        held.push(query);
    }
    assert!(held.len() < QUEUE_LEN);
    assert_eq!(audit.admission.counters.dropped.load(Ordering::Relaxed), 1);
    drop(held);
    while receiver.try_recv().is_ok() {}
    assert_eq!(audit.admission.bytes.available_permits(), QUEUE_BYTES);
}

#[test]
fn response_admission_failure_discards_whole_event_without_false_cancellation() {
    let (sender, mut receiver) = mpsc::channel(QUEUE_LEN);
    let audit = DnsAudit {
        sender: Some(sender),
        admission: Arc::default(),
    };
    let pending = audit
        .begin(
            &query(),
            IngressProfile::Tcp,
            "192.0.2.1:53".parse().unwrap(),
        )
        .unwrap();
    let remaining = audit.admission.bytes.available_permits();
    let held = Arc::clone(&audit.admission.bytes)
        .try_acquire_many_owned(remaining as u32)
        .unwrap();
    pending.finish(&crate::dns::response::build_dns_refused(&query()), None);
    assert!(receiver.try_recv().is_err());
    assert_eq!(audit.admission.counters.dropped.load(Ordering::Relaxed), 1);
    drop(held);
    assert_eq!(audit.admission.bytes.available_permits(), QUEUE_BYTES);
}

#[test]
fn oversized_unknown_rr_round_trips_without_clipping() {
    let query = crate::dns::forwarder::build_dns_query("large.example", 65000);
    let mut response = query.clone();
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 12, 0xfd, 0xe8, 0, 1, 0, 0, 0, 1]);
    response.extend_from_slice(&60000u16.to_be_bytes());
    response.resize(response.len() + 60000, 0xab);
    let mut input = entry(response);
    input.query = query.into();
    let value = encode(&input, "instance:1").unwrap();
    assert_eq!(
        value["answers"][0]["data"],
        format!("\\# 60000 {}", "AB".repeat(60000))
    );
    assert_eq!(value["answer_ips"], json!([]));
    assert_eq!(value["answer_cnames"], json!([]));
    assert_eq!(value["answer_types"], json!(["TYPE65000"]));
    let bytes = frame(&value, input.completed, &identity()).unwrap();
    assert!(bytes.len() > 8192);
    assert_eq!(decode_frame(&bytes), value);
}

#[test]
fn derived_search_arrays_deduplicate_without_removing_answers() {
    let mut response = query();
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    let records: &[(u16, &[u8])] = &[
        (5, b"\x04edge\x07example\0"),
        (1, &[203, 0, 113, 20]),
        (1, &[203, 0, 113, 20]),
        (
            28,
            &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        (5, b"\x04edge\x07example\0"),
        (16, b"\x03foo"),
        (65000, &[0xab]),
    ];
    response[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    for (rtype, data) in records {
        response.extend_from_slice(&[0xc0, 12]);
        response.extend_from_slice(&rtype.to_be_bytes());
        response.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(data);
    }
    let value = encode(&entry(response), "instance:1").unwrap();
    assert_eq!(
        value["message"],
        "DNS 192.0.2.8 audit.example. A IN: NOERROR answers=7"
    );
    assert_eq!(value["answers"].as_array().unwrap().len(), records.len());
    assert_eq!(value["answer_ips"], json!(["203.0.113.20", "2001:db8::1"]));
    assert_eq!(value["answer_cnames"], json!(["edge.example."]));
    assert_eq!(
        value["answer_types"],
        json!(["CNAME", "A", "AAAA", "TXT", "TYPE65000"])
    );
}

#[test]
fn configured_identity_is_only_in_rfc_header() {
    let global = honk_config::config::GlobalConfig {
        syslog_hostname: "gateway.example".into(),
        syslog_app_name: "dns-audit".into(),
        ..Default::default()
    };
    let identity = Identity::from_config(&global);
    let input = entry(crate::dns::response::build_dns_refused(&query()));
    let value = encode(&input, "instance:1").unwrap();
    assert!(value.get("hostname").is_none());
    assert!(value.get("app_name").is_none());
    for (cee, marker) in [(false, ""), (true, "@cee: ")] {
        let bytes = super::frame(&value, SystemTime::UNIX_EPOCH, &identity, cee).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let (length, message) = text.split_once(' ').unwrap();
        assert_eq!(length.parse::<usize>().unwrap(), message.len());
        let (header, body) = message.split_once('{').unwrap();
        assert_eq!(
            header,
            format!(
                "<134>1 1970-01-01T00:00:00.000000Z gateway.example dns-audit - dns.query - {marker}"
            )
        );
        let parsed: serde_json::Value = serde_json::from_str(&format!("{{{body}")).unwrap();
        assert_eq!(parsed, value);
    }
}

#[test]
fn automatic_hostname_uses_only_valid_system_values() {
    assert_eq!(Identity::system_hostname("router01\n"), "router01");
    assert_eq!(Identity::system_hostname("router01"), "router01");
    for invalid in ["", "with space\n", "router\n\n", "\r\n", "路由器\n"] {
        assert_eq!(Identity::system_hostname(invalid), "-");
    }
    assert_eq!(Identity::system_hostname(&"x".repeat(256)), "-");
}

#[test]
fn whole_event_limit_includes_header_and_utf8_framing_counts_bytes() {
    let identity = Identity {
        hostname: "h".repeat(255),
        app_name: "a".repeat(48),
    };
    let time = SystemTime::UNIX_EPOCH;
    let mut value = json!({"padding": ""});
    let overhead = identity.header(time, true).len() + serde_json::to_vec(&value).unwrap().len();
    value["padding"] = json!("x".repeat(MAX_EVENT_BYTES - overhead));
    let at_limit = frame(&value, time, &identity).unwrap();
    assert!(at_limit.starts_with(format!("{MAX_EVENT_BYTES} ").as_bytes()));
    assert_eq!(decode_frame(&at_limit), value);
    value["padding"] = json!("x".repeat(MAX_EVENT_BYTES - overhead + 1));
    assert!(frame(&value, time, &identity).is_err());
    let utf8 = json!({"label": "上海"});
    let bytes = frame(&utf8, time, &identity).unwrap();
    assert_eq!(decode_frame(&bytes), utf8);
    let text = std::str::from_utf8(&bytes).unwrap();
    let (length, message) = text.split_once(' ').unwrap();
    assert_eq!(length.parse::<usize>().unwrap(), message.len());
    assert!(message.len() > message.chars().count());
}

#[test]
fn compressed_aaaa_answers_expand_past_the_syslog_budget() {
    let query = crate::dns::forwarder::build_dns_query("audit.example", 28);
    let mut response = query.clone();
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    response[6..8].copy_from_slice(&100u16.to_be_bytes());
    for index in 1u16..=100 {
        response.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        let mut ip = "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap().octets();
        ip[14..].copy_from_slice(&index.to_be_bytes());
        response.extend_from_slice(&ip);
    }
    let wire_bytes = response.len();
    let mut input = entry(response);
    input.query = query.into();
    let value = encode(&input, "instance:1").unwrap();
    let json_bytes = serde_json::to_vec(&value).unwrap().len();
    let bytes = frame(&value, input.completed, &identity()).unwrap();
    assert!(wire_bytes < 4096);
    assert!(json_bytes > 8192);
    assert_eq!(value["answers"].as_array().unwrap().len(), 100);
    assert_eq!(value["answer_ips"].as_array().unwrap().len(), 100);
    assert_eq!(decode_frame(&bytes), value);
    println!(
        "100 compressed AAAA answers: DNS wire={wire_bytes} bytes, audit JSON={json_bytes} bytes, single TCP frame={} bytes",
        bytes.len()
    );
}

#[test]
fn unrenderable_answer_data_keeps_the_event_without_answers() {
    let mut response = query();
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    // Five RDATA bytes form a valid record boundary but not an IPv4 address.
    response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 5, 192, 0, 2, 1, 9]);
    let value = encode(&entry(response), "instance:1").unwrap();
    assert_eq!(value["rcode"], "NOERROR");
    assert_eq!(value["answers"], json!(null));
    assert_eq!(value["answers_omitted"], "invalid");
    assert_eq!(value["answer_ips"], json!([]));
    assert_eq!(
        value["message"],
        "DNS 192.0.2.8 audit.example. A IN: NOERROR answers=invalid"
    );
}

#[test]
fn optional_cee_prefix_counts_toward_the_whole_message_limit() {
    let identity = identity();
    let time = SystemTime::UNIX_EPOCH;
    let mut value = json!({"padding":""});
    let overhead = identity.header(time, false).len() + serde_json::to_vec(&value).unwrap().len();
    value["padding"] = json!("x".repeat(MAX_EVENT_BYTES - overhead));
    assert!(super::frame(&value, time, &identity, false).is_ok());
    assert!(super::frame(&value, time, &identity, true).is_err());
    value["padding"] = json!("x".repeat(MAX_EVENT_BYTES - overhead - 6));
    let framed = super::frame(&value, time, &identity, true).unwrap();
    assert!(framed.starts_with(format!("{MAX_EVENT_BYTES} ").as_bytes()));
    assert_eq!(decode_frame(&framed), value);
}
