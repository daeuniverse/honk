//! HTTP connection, observer and credential-worker ownership.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use axum::Extension;
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use super::types::{TrafficBytes, TrafficConnections, TrafficRates, TrafficSummary};
use super::{NativeState, Peer, router, timestamp};
use crate::connection_tracker::ConnectionTracker;

pub(super) async fn sample_traffic(state: Arc<NativeState>, mut stop: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut previous: Option<(Instant, Option<(u64, u64)>)> = None;
    let mut previous_cpu: Option<(Instant, Duration)> = None;
    let mut trace_failing = false;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = interval.tick() => {
                state.observation.settings.maintain(&state.observation);
                reconcile_kernel_trace(&state, &mut trace_failing).await;
                state.observation.core.flows.maintain();
                let now = Instant::now();
                let totals = state.stats.traffic_totals();
                let rates = previous.and_then(|(instant, old)| {
                    let elapsed = now.duration_since(instant);
                    let (old_up, old_down) = old?;
                    let (up, down) = totals?;
                    let up = up.checked_sub(old_up)?;
                    let down = down.checked_sub(old_down)?;
                    if elapsed.is_zero() { return None; }
                    let rate = |bytes: u64| u64::try_from(u128::from(bytes) * 1_000_000_000 / elapsed.as_nanos()).ok().map(|value| value.to_string());
                    Some(TrafficRates { window_seconds: elapsed.as_secs_f64(), upload_bytes_per_second: rate(up), download_bytes_per_second: rate(down) })
                });
                let (mut tcp, mut udp) = (0u64, 0u64);
                state.tracker.visit(|entry| match entry.network.as_str() { "tcp" => tcp += 1, "udp" => udp += 1, _ => {} });
                *state.sample.write() = Some(TrafficSummary {
                    scope: "visible", observed_by: "userspace", counter_since: Some(timestamp(state.stats.counter_since())), sampled_at: Some(timestamp(SystemTime::now())),
                    connections: TrafficConnections { tcp: Some(tcp), udp: Some(udp), total: Some(tcp + udp) },
                    bytes: TrafficBytes { upload: totals.map(|bytes| bytes.0.to_string()), download: totals.map(|bytes| bytes.1.to_string()) }, rates,
                });
                previous = Some((now, totals));
                let cpu = process_cpu_time().map(|time| (now, time));
                *state.cpu_percent.write() = previous_cpu.zip(cpu).and_then(|(old, new)| cpu_percent(old, new));
                previous_cpu = cpu;
                let sample = state.sample.read().clone().expect("sample published above");
                state.observation.telemetry.sample(&sample).await;
                state.observation.events.publish("runtime.updated", serde_json::json!({}), None);
            }
        }
    }
}

/// Settings owns demand; the existing sampler publishes it on its next tick.
/// Scheduling and publication/telemetry contention can delay that tick.
/// A persistent failure repeats every tick; warn once per episode.
async fn reconcile_kernel_trace(state: &NativeState, failing: &mut bool) {
    let Some(flags) = &state.datapath_flags else {
        return;
    };
    match flags
        .reconcile_kernel_trace(|| state.observation.settings.flow_recording())
        .await
    {
        Ok(()) => {
            if std::mem::replace(failing, false) {
                tracing::info!("kernel trace admission recovered");
            }
        }
        Err(error) => {
            crate::logging::warn_on_entry!(
                !std::mem::replace(failing, true),
                %error,
                "kernel trace admission retains its previous state"
            );
        }
    }
}

fn process_cpu_time() -> Option<Duration> {
    nix::time::clock_gettime(nix::time::ClockId::CLOCK_PROCESS_CPUTIME_ID)
        .ok()
        .map(Duration::from)
}

/// Process CPU time over the wall interval as a percentage of one CPU, so a busy multi-threaded process exceeds 100.
pub(super) fn cpu_percent(previous: (Instant, Duration), now: (Instant, Duration)) -> Option<f64> {
    let wall = now.0.checked_duration_since(previous.0)?;
    let cpu = now.1.checked_sub(previous.1)?;
    (!wall.is_zero()).then(|| cpu.as_secs_f64() / wall.as_secs_f64() * 100.0)
}

struct NativeConsumer(Arc<ConnectionTracker>);
impl Drop for NativeConsumer {
    fn drop(&mut self) {
        self.0.disable_native();
    }
}

/// Owns HTTP connections through bounded grace, then joins admitted credential work.
pub struct NativeServer {
    stop: watch::Sender<bool>,
    supervisor: JoinHandle<()>,
}

impl NativeServer {
    pub fn start(listener: TcpListener, state: Arc<NativeState>) -> Self {
        let (stop, receiver) = watch::channel(false);
        state.tracker.enable_native();
        let consumer = NativeConsumer(Arc::clone(&state.tracker));
        let supervisor = tokio::spawn(supervise(listener, state, receiver, consumer));
        Self { stop, supervisor }
    }

    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        if self.supervisor.await.is_err() {
            tracing::error!(message = "native HTTP supervisor failed");
        }
    }
}

const RECEIVING: u8 = 0;
const ANSWERING: u8 = 1;
const ANSWERED: u8 = 2;

/// Marks one request busy from its last body byte until its response resolves.
struct Busy {
    state: AtomicU8,
    connection: Arc<AtomicUsize>,
}

impl Busy {
    fn received(&self) {
        if self
            .state
            .compare_exchange(RECEIVING, ANSWERING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.connection.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn answered(&self) {
        if self.state.swap(ANSWERED, Ordering::AcqRel) == ANSWERING {
            self.connection.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

// Busy starts only after the body ends, so read idleness still bounds peers that stall mid-body.
struct Tracked {
    body: Incoming,
    busy: Arc<Busy>,
}

impl Body for Tracked {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let frame = std::pin::Pin::new(&mut self.body).poll_frame(cx);
        if matches!(frame, std::task::Poll::Ready(None)) || self.body.is_end_stream() {
            self.busy.received();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

struct NativeIo {
    stream: TcpStream,
    idle: std::pin::Pin<Box<tokio::time::Sleep>>,
    write_idle: std::pin::Pin<Box<tokio::time::Sleep>>,
    write_pending: bool,
    busy: Arc<AtomicUsize>,
    was_busy: bool,
}

impl NativeIo {
    fn new(stream: TcpStream, busy: Arc<AtomicUsize>) -> Self {
        Self {
            stream,
            idle: Box::pin(tokio::time::sleep(Duration::from_secs(30))),
            write_idle: Box::pin(tokio::time::sleep(Duration::from_secs(30))),
            write_pending: false,
            busy,
            was_busy: false,
        }
    }

    fn progress(&mut self) {
        self.idle
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_secs(30));
    }

    fn pending_write(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::future::Future;
        if !self.write_pending {
            self.write_pending = true;
            self.write_idle
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_secs(30));
        }
        if self.write_idle.as_mut().poll(cx).is_ready() {
            std::task::Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()))
        } else {
            std::task::Poll::Pending
        }
    }
}

impl tokio::io::AsyncRead for NativeIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::future::Future;
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(result, std::task::Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.progress();
        }
        // hyper keeps a read pending while a handler runs; the peer owes nothing until it answers.
        if self.busy.load(Ordering::Acquire) > 0 {
            self.was_busy = true;
            return result;
        }
        if std::mem::take(&mut self.was_busy) {
            self.progress();
        }
        if result.is_pending() && self.idle.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        result
    }
}

impl tokio::io::AsyncWrite for NativeIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.stream).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = result
            && n > 0
        {
            self.progress();
            self.write_pending = false;
        }
        if result.is_pending() {
            self.pending_write(cx)
        } else {
            result
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn serve<S>(stream: TcpStream, service: S, mut stop: watch::Receiver<bool>)
where
    S: tower::Service<
            hyper::Request<Tracked>,
            Response = axum::response::Response,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    let busy = Arc::new(AtomicUsize::new(0));
    let io = NativeIo::new(stream, Arc::clone(&busy));
    let service = TowerToHyperService::new(service);
    let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
        let request_busy = Arc::new(Busy {
            state: AtomicU8::new(RECEIVING),
            connection: Arc::clone(&busy),
        });
        if request.body().is_end_stream() {
            request_busy.received();
        }
        let tracked = Arc::clone(&request_busy);
        let response = hyper::service::Service::call(
            &service,
            request.map(|body| Tracked {
                body,
                busy: tracked,
            }),
        );
        async move {
            let response = response.await;
            request_busy.answered();
            response
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5))
        .max_headers(100)
        .max_buf_size(32768);
    let connection = builder.serve_connection(TokioIo::new(io), service);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => { let _ = result; }
        _ = stop.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}

async fn supervise(
    listener: TcpListener,
    state: Arc<NativeState>,
    mut stop: watch::Receiver<bool>,
    _consumer: NativeConsumer,
) {
    let router = router(Arc::clone(&state));
    let observation = Arc::clone(&state.observation);
    let (sampler_stop, sampler_receiver) = watch::channel(false);
    let (connections_stop, connection_receiver) = watch::channel(false);
    let (probes_stop, probes_receiver) = watch::channel(false);
    let mut probes = observation
        .probes
        .start(Arc::clone(&state), probes_receiver);
    let mut probes_running = true;
    let (schedule_stop, schedule_receiver) = watch::channel(false);
    let mut schedule = tokio::spawn(super::geodata::schedule(
        Arc::clone(&state),
        schedule_receiver,
    ));
    let mut schedule_running = true;
    let mut sampler = tokio::spawn(sample_traffic(Arc::clone(&state), sampler_receiver));
    let mut sampler_running = true;
    let mut children = JoinSet::new();
    // A persistent accept error repeats every iteration; warn once per episode.
    let mut accept_failing = false;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = &mut probes => {
                probes_running = false;
                tracing::error!(message = "native probe supervisor stopped unexpectedly");
                break;
            }
            _ = &mut sampler => {
                sampler_running = false;
                tracing::error!(message = "native HTTP sampler stopped unexpectedly");
                break;
            }
            _ = &mut schedule => {
                schedule_running = false;
                tracing::error!(message = "native geodata schedule stopped unexpectedly");
                break;
            }
            child = children.join_next(), if !children.is_empty() => {
                if child.is_some_and(|result| result.is_err()) {
                    tracing::error!(message = "native HTTP connection task failed");
                }
            }
            accepted = listener.accept(), if children.len() < 64 => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        crate::logging::warn_on_entry!(
                            !std::mem::replace(&mut accept_failing, true),
                            message = "native HTTP listener failed"
                        );
                        // Resource exhaustion persists across retries; back off instead of spinning.
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
                        ) {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        continue;
                    }
                };
                if std::mem::replace(&mut accept_failing, false) {
                    tracing::info!(message = "native HTTP listener recovered");
                }
                let peer = Peer(peer.ip().to_canonical());
                let service = tower::Layer::layer(&Extension(peer), router.clone());
                children.spawn(serve(stream, service, connection_receiver.clone()));
            }
        }
    }
    drop(listener);
    if let Some(auth) = &state.auth {
        auth.close();
    }
    let _ = probes_stop.send(true);
    if probes_running {
        let _ = probes.await;
    }
    observation.settings.shutdown(&observation);
    observation.logs.shutdown();
    observation.events.shutdown();
    let _ = sampler_stop.send(true);
    if sampler_running {
        let _ = sampler.await;
    }
    reconcile_kernel_trace(&state, &mut false).await;
    let _ = schedule_stop.send(true);
    if schedule_running {
        let _ = schedule.await;
    }
    let _ = connections_stop.send(true);
    if tokio::time::timeout(Duration::from_secs(5), async {
        while children.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        children.abort_all();
        while children.join_next().await.is_some() {}
    }
    if let Some(auth) = &state.auth {
        auth.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn connect(router: axum::Router) -> (TcpStream, JoinHandle<()>, watch::Sender<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let (stop, receiver) = watch::channel(false);
        (client, tokio::spawn(serve(stream, router, receiver)), stop)
    }

    #[tokio::test(start_paused = true)]
    async fn slow_handler_outlives_read_idle() {
        let router = axum::Router::new().route(
            "/",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                "done"
            }),
        );
        let (mut client, _server, _stop) = connect(router).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: honk\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let mut chunk = [0; 1024];
        while !response.ends_with(b"done") {
            let read = client.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "connection closed before the response");
            response.extend_from_slice(&chunk[..read]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_request_body_still_times_out() {
        let router = axum::Router::new().route(
            "/",
            axum::routing::post(|body: Bytes| async move { body.len().to_string() }),
        );
        let (mut client, server, _stop) = connect(router).await;
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: honk\r\nContent-Length: 10\r\n\r\nabc")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(60), server)
            .await
            .expect("a peer stalling mid-body must be disconnected")
            .unwrap();
    }
}
