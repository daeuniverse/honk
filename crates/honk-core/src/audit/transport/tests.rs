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

fn identity() -> Identity {
    Identity {
        hostname: "router01".into(),
        app_name: "honk".into(),
    }
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
    let value = json!({"event": label, "completed_at": timestamp(SystemTime::UNIX_EPOCH)});
    batch.push(frame(&value, SystemTime::UNIX_EPOCH, &identity(), true).unwrap());
    batch
}

#[tokio::test(start_paused = true)]
async fn continuous_arrivals_do_not_postpone_the_oldest_batch_deadline() {
    let sink = Sink::default();
    let connector = connector(vec![Ok(sink.writer())]);
    let attempts = Arc::clone(&connector.attempts);
    let (audit, mut worker) = DnsAuditWorker::with_connector(connector, identity(), true);
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
        DnsAuditWorker::with_connector(connector(vec![Ok(sink.writer())]), identity(), true);
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
        let (audit, mut worker) = DnsAuditWorker::with_connector(connector, identity(), true);
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
        DnsAuditWorker::with_connector(connector(vec![Ok(sink.writer())]), identity(), true);
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

#[tokio::test(start_paused = true)]
async fn sender_preserves_plain_json_and_cee_modes() {
    for cee in [false, true] {
        let sink = Sink::default();
        let (audit, mut worker) =
            DnsAuditWorker::with_connector(connector(vec![Ok(sink.writer())]), identity(), cee);
        complete(&audit, "mode.example");
        tokio::task::yield_now().await;
        tokio::time::advance(FLUSH_INTERVAL).await;
        tokio::task::yield_now().await;
        let bytes = sink.bytes.lock().clone();
        let text = std::str::from_utf8(&bytes).unwrap();
        let message = text.split_once(' ').unwrap().1;
        assert_eq!(message.split(' ').nth(2), Some("router01"));
        assert_eq!(message.split(' ').nth(3), Some("honk"));
        let body = message.splitn(8, ' ').nth(7).unwrap();
        assert_eq!(body.starts_with("@cee: "), cee);
        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["domain"], "mode.example.");
        assert_eq!(events[0]["event"], "dns.query");
        assert!(events[0].get("hostname").is_none());
        assert!(events[0].get("app_name").is_none());
        worker.shutdown().await;
    }
}
