use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::*;

#[derive(Clone, Default)]
struct Sink {
    bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
    writes: Arc<AtomicU64>,
}

impl Sink {
    fn writer(&self) -> Writer {
        Writer {
            sink: self.clone(),
            fail_after: None,
            stalled: false,
        }
    }

    fn events(&self) -> Vec<serde_json::Value> {
        let bytes = self.bytes.lock();
        let mut rest = bytes.as_slice();
        let mut events = Vec::new();
        while !rest.is_empty() {
            let split = rest.iter().position(|byte| *byte == b' ').unwrap();
            let length: usize = std::str::from_utf8(&rest[..split])
                .unwrap()
                .parse()
                .unwrap();
            let message = std::str::from_utf8(&rest[split + 1..split + 1 + length]).unwrap();
            events.push(
                serde_json::from_str(
                    message
                        .splitn(8, ' ')
                        .nth(7)
                        .unwrap()
                        .strip_prefix("@cee: ")
                        .unwrap_or(message.splitn(8, ' ').nth(7).unwrap()),
                )
                .unwrap(),
            );
            rest = &rest[split + 1 + length..];
        }
        events
    }
}

struct Writer {
    sink: Sink,
    fail_after: Option<usize>,
    stalled: bool,
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.stalled {
            return Poll::Pending;
        }
        let mut output = this.sink.bytes.lock();
        let remaining = this
            .fail_after
            .map_or(usize::MAX, |limit| limit.saturating_sub(output.len()));
        if remaining == 0 {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let count = remaining.min(bytes.len());
        output.extend_from_slice(&bytes[..count]);
        this.sink.writes.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct ScriptConnector {
    outcomes: VecDeque<io::Result<Writer>>,
    attempts: Arc<AtomicU64>,
    stalled: bool,
}

impl Connector for ScriptConnector {
    type Stream = Writer;
    async fn connect(&mut self) -> io::Result<Writer> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if self.stalled {
            return std::future::pending().await;
        }
        self.outcomes
            .pop_front()
            .unwrap_or_else(|| Err(io::ErrorKind::ConnectionRefused.into()))
    }
}

fn connector(outcomes: Vec<io::Result<Writer>>) -> ScriptConnector {
    ScriptConnector {
        outcomes: outcomes.into(),
        attempts: Arc::default(),
        stalled: false,
    }
}

fn identity() -> Profile {
    crate::audit::tests::profile(Identity {
        hostname: "router01".into(),
        app_name: "honk".into(),
    })
}

fn complete(audit: &DnsAudit, name: &str) {
    let query = crate::dns::forwarder::build_dns_query(name, 1);
    audit
        .begin(
            &query,
            IngressProfile::Tcp,
            "192.0.2.4:53000".parse().unwrap(),
        )
        .unwrap()
        .finish(&crate::dns::response::build_dns_refused(&query), None);
}

fn transport(connector: ScriptConnector) -> Transport<ScriptConnector> {
    Transport {
        connector,
        stream: None,
        backoff: INITIAL_BACKOFF,
        retry_at: None,
        admission: Arc::default(),
    }
}

fn batch(label: &str) -> Batch {
    let mut batch = Batch::default();
    let value = json!({"event": label, "hostname": "router01", "app_name": "honk", "completed_at": timestamp(SystemTime::UNIX_EPOCH)});
    batch.push(frame(&value, &identity()).unwrap());
    batch
}

fn publish(audit: &DnsAudit, config: &honk_config::config::GlobalConfig) {
    audit
        .prepare_publication(audit.prepare_format(config).unwrap())
        .unwrap()
        .commit();
}

#[tokio::test(start_paused = true)]
async fn queued_and_inflight_queries_keep_their_template_across_live_connection_reload() {
    let sink = Sink::default();
    let connector = connector(vec![Ok(sink.writer())]);
    let attempts = Arc::clone(&connector.attempts);
    let (audit, mut worker) = DnsAuditWorker::with_connector(connector, identity());
    let old = Arc::downgrade(audit.format.read().as_ref().unwrap());
    let query = crate::dns::forwarder::build_dns_query("inflight.example", 1);
    let pending = audit
        .begin(&query, IngressProfile::Tcp, "192.0.2.1:53".parse().unwrap())
        .unwrap();
    let cancelled = audit
        .begin(&query, IngressProfile::Tcp, "192.0.2.1:53".parse().unwrap())
        .unwrap();
    complete(&audit, "queued.example");
    let mut next = honk_config::config::GlobalConfig {
        syslog_dns_json: r#"{"format":"new","domain":"${domain}","revision":"${template_version}","message":"${message}"}"#.into(),
        ..Default::default()
    };
    publish(&audit, &next);
    pending.finish(&crate::dns::response::build_dns_refused(&query), None);
    drop(cancelled);
    complete(&audit, "after.example");
    tokio::task::yield_now().await;
    tokio::time::advance(FLUSH_INTERVAL).await;
    tokio::task::yield_now().await;
    let events = sink.events();
    assert_eq!(events.len(), 4);
    for event in &events[..3] {
        assert_eq!(event["event"], "dns.query");
        assert!(event.get("format").is_none());
    }
    assert_eq!(events[2]["result"], "cancelled");
    assert!(events[2]["rcode"].is_null());
    assert_eq!(events[3]["format"], "new");
    assert_eq!(events[3]["domain"], "after.example.");
    assert!(old.upgrade().is_none());
    let revision = events[3]["revision"].clone();
    next.syslog_dns_json = next.syslog_dns_json.replace("new", "newer");
    publish(&audit, &next);
    complete(&audit, "later.example");
    tokio::task::yield_now().await;
    tokio::time::advance(FLUSH_INTERVAL).await;
    tokio::task::yield_now().await;
    let events = sink.events();
    assert_eq!(events[4]["format"], "newer");
    assert_ne!(events[4]["revision"], revision);
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    worker.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn retained_template_versions_are_bounded_and_unchanged_templates_need_no_slot() {
    let sink = Sink::default();
    let (audit, mut worker) =
        DnsAuditWorker::with_connector(connector(vec![Ok(sink.writer())]), identity());
    let mut holders = Vec::new();
    let mut config = honk_config::config::GlobalConfig::default();
    for index in 1..8 {
        let query = crate::dns::forwarder::build_dns_query("pending.example", 1);
        holders.push(
            audit
                .begin(&query, IngressProfile::Tcp, "192.0.2.1:53".parse().unwrap())
                .unwrap(),
        );
        config.syslog_dns_json = format!(r#"{{"version":{index}}}"#);
        publish(&audit, &config);
    }
    assert_eq!(audit.admission.formats.available_permits(), 0);
    assert!(audit.prepare_format(&config).unwrap().is_none());
    let unchanged = audit.format.read().clone().unwrap();
    config.syslog_dns_json = r#"{"version":8}"#.into();
    assert!(audit.prepare_format(&config).is_err());
    assert!(Arc::ptr_eq(
        audit.format.read().as_ref().unwrap(),
        &unchanged
    ));
    drop(unchanged);
    for mut pending in holders {
        pending.entry.take();
        pending.permit.take();
    }
    assert_eq!(audit.admission.formats.available_permits(), 7);
    let mut invalid = config.clone();
    invalid.syslog_dns_json = r#"{"bad":"${unknown}"}"#.into();
    assert!(audit.prepare_format(&invalid).is_err());
    assert_eq!(audit.admission.formats.available_permits(), 7);
    publish(&audit, &config);
    assert_eq!(audit.admission.formats.available_permits(), 7);
    worker.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn continuous_arrivals_do_not_postpone_the_oldest_batch_deadline() {
    let sink = Sink::default();
    let connector = connector(vec![Ok(sink.writer())]);
    let attempts = Arc::clone(&connector.attempts);
    let (audit, mut worker) = DnsAuditWorker::with_connector(connector, identity());
    complete(&audit, "first.example");
    tokio::task::yield_now().await;
    for index in 1..5 {
        tokio::time::advance(Duration::from_millis(200)).await;
        complete(&audit, &format!("next{index}.example"));
        tokio::task::yield_now().await;
    }
    assert!(sink.bytes.lock().is_empty());
    tokio::time::advance(Duration::from_millis(200)).await;
    tokio::task::yield_now().await;
    assert_eq!(sink.events().len(), 5);
    assert_eq!(sink.writes.load(Ordering::Relaxed), 1);
    complete(&audit, "later.example");
    tokio::task::yield_now().await;
    tokio::time::advance(FLUSH_INTERVAL).await;
    tokio::task::yield_now().await;
    assert_eq!(sink.events().len(), 6);
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    assert_eq!(audit.admission.bytes.available_permits(), QUEUE_BYTES);
    worker.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn full_batches_flush_without_waiting_for_timer() {
    let sink = Sink::default();
    let (audit, mut worker) =
        DnsAuditWorker::with_connector(connector(vec![Ok(sink.writer())]), identity());
    for index in 0..400 {
        complete(&audit, &format!("event{index}.example"));
    }
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    let immediate = sink.events().len();
    assert!(immediate > 0 && immediate < 400);
    tokio::time::advance(FLUSH_INTERVAL).await;
    tokio::task::yield_now().await;
    assert_eq!(sink.events().len(), 400);
    assert!(sink.writes.load(Ordering::Relaxed) < 400);
    worker.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn connection_failure_keeps_batch_and_backs_off_before_reconnect() {
    let sink = Sink::default();
    let connector = connector(vec![
        Err(io::ErrorKind::ConnectionRefused.into()),
        Err(io::ErrorKind::ConnectionRefused.into()),
        Ok(sink.writer()),
    ]);
    let attempts = Arc::clone(&connector.attempts);
    let mut transport = transport(connector);
    let started = Instant::now();
    let mut batch = batch("retained");
    transport.send(&mut batch).await;
    assert_eq!(Instant::now() - started, Duration::from_millis(750));
    assert_eq!(attempts.load(Ordering::Relaxed), 3);
    assert_eq!(sink.events()[0]["event"], "retained");
    assert_eq!(transport.backoff, INITIAL_BACKOFF);
    assert_eq!(
        transport
            .admission
            .counters
            .connect_failed
            .load(Ordering::Relaxed),
        2
    );
    assert_eq!(batch.events, 0);
}

#[tokio::test(start_paused = true)]
async fn partial_write_is_not_replayed_on_the_next_connection() {
    let first = Sink::default();
    let second = Sink::default();
    let mut failing = first.writer();
    failing.fail_after = Some(12);
    let mut transport = transport(connector(vec![Ok(failing), Ok(second.writer())]));
    transport.send(&mut batch("ambiguous")).await;
    assert_eq!(first.bytes.lock().len(), 12);
    assert_eq!(
        transport
            .admission
            .counters
            .send_failed
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(transport.backoff, INITIAL_BACKOFF * 2);
    transport.send(&mut batch("new-event")).await;
    let events = second.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "new-event");
    assert_eq!(transport.backoff, INITIAL_BACKOFF);
}

#[tokio::test(start_paused = true)]
async fn stalled_write_times_out_and_discards_only_its_batch() {
    let sink = Sink::default();
    let mut writer = sink.writer();
    writer.stalled = true;
    let mut transport = transport(connector(vec![Ok(writer)]));
    let started = Instant::now();
    let mut batch = batch("timeout");
    transport.send(&mut batch).await;
    assert_eq!(Instant::now() - started, IO_TIMEOUT);
    assert_eq!(batch.events, 0);
    assert!(sink.bytes.lock().is_empty());
    assert!(transport.stream.is_none());
    assert_eq!(
        transport.admission.counters.dropped.load(Ordering::Relaxed),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn accepted_connections_with_failed_writes_do_not_reset_backoff() {
    let sink = Sink::default();
    let mut first = sink.writer();
    first.fail_after = Some(0);
    let mut second = sink.writer();
    second.fail_after = Some(0);
    let mut transport = transport(connector(vec![Ok(first), Ok(second)]));
    transport.send(&mut batch("first")).await;
    assert_eq!(transport.backoff, INITIAL_BACKOFF * 2);
    transport.send(&mut batch("second")).await;
    assert_eq!(transport.backoff, INITIAL_BACKOFF * 4);
    assert_eq!(
        transport
            .admission
            .counters
            .send_failed
            .load(Ordering::Relaxed),
        2
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_interrupts_connect_backoff_and_write_waits() {
    for mode in ["connect", "backoff", "write"] {
        let sink = Sink::default();
        let mut writer = sink.writer();
        writer.stalled = true;
        let mut connector = connector(if mode == "write" {
            vec![Ok(writer)]
        } else {
            vec![]
        });
        connector.stalled = mode == "connect";
        let (audit, mut worker) = DnsAuditWorker::with_connector(connector, identity());
        complete(&audit, "pending.example");
        tokio::task::yield_now().await;
        tokio::time::advance(FLUSH_INTERVAL).await;
        tokio::task::yield_now().await;
        let started = Instant::now();
        worker.shutdown().await;
        assert!(Instant::now() - started <= FLUSH_INTERVAL, "{mode}");
        assert!(audit.admission.stopped.load(Ordering::Acquire));
        assert_eq!(audit.admission.bytes.available_permits(), QUEUE_BYTES);
        assert_eq!(audit.admission.counters.dropped.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn one_large_dns_event_is_sent_whole_in_its_own_batch() {
    let sink = Sink::default();
    let (audit, mut worker) =
        DnsAuditWorker::with_connector(connector(vec![Ok(sink.writer())]), identity());
    let query = crate::dns::forwarder::build_dns_query("large.example", 16);
    let mut response = query.clone();
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60]);
    response.extend_from_slice(&51200u16.to_be_bytes());
    for _ in 0..200 {
        response.push(255);
        response.extend_from_slice(&[0xff; 255]);
    }
    audit
        .begin(
            &query,
            IngressProfile::Tcp,
            "192.0.2.4:53000".parse().unwrap(),
        )
        .unwrap()
        .finish(&response, None);
    tokio::task::yield_now().await;
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "dns.query");
    assert_eq!(events[0]["answers"].as_array().unwrap().len(), 1);
    assert!(events[0]["answers"][0]["data"].as_str().unwrap().len() > BATCH_BYTES);
    assert_eq!(events[0]["answer_types"], json!(["TXT"]));
    assert_eq!(sink.writes.load(Ordering::Relaxed), 1);
    worker.shutdown().await;
}
