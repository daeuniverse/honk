//! One TCP connection owner, bounded batching and cancellation-aware reconnects.

use std::future::Future;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio::time::Instant;

use super::*;

const BATCH_BYTES: usize = 128 * 1024;
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub(super) trait Connector: Send + 'static {
    type Stream: AsyncWrite + Unpin + Send;
    fn connect(&mut self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

struct TcpConnector {
    target: SocketAddr,
    mark: u32,
}

impl Connector for TcpConnector {
    type Stream = TcpStream;

    async fn connect(&mut self) -> io::Result<TcpStream> {
        let socket = if self.target.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        // Never let audit output recurse through honk's own interception path.
        #[cfg(target_os = "linux")]
        socket2::SockRef::from(&socket).set_mark(self.mark)?;
        let stream = socket.connect(self.target).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

#[derive(Default)]
struct Batch {
    bytes: Vec<u8>,
    events: u64,
}

impl Batch {
    fn push(&mut self, bytes: Vec<u8>) {
        if self.events == 0 && bytes.len() > BATCH_BYTES {
            self.bytes = bytes;
        } else {
            self.bytes.extend_from_slice(&bytes);
        }
        self.events += 1;
    }

    fn clear(&mut self) {
        self.events = 0;
        if self.bytes.capacity() > BATCH_BYTES * 2 {
            self.bytes = Vec::new();
        } else {
            self.bytes.clear();
        }
    }
}

struct Transport<C: Connector> {
    connector: C,
    stream: Option<C::Stream>,
    backoff: Duration,
    retry_at: Option<Instant>,
    admission: Arc<Admission>,
}

impl<C: Connector> Transport<C> {
    fn failed(&mut self) {
        self.stream.take();
        self.retry_at = Some(Instant::now() + self.backoff);
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }

    async fn send(&mut self, batch: &mut Batch) {
        while self.stream.is_none() {
            if let Some(deadline) = self.retry_at.take() {
                tokio::time::sleep_until(deadline).await;
            }
            match tokio::time::timeout(IO_TIMEOUT, self.connector.connect()).await {
                Ok(Ok(stream)) => self.stream = Some(stream),
                failure => {
                    self.admission
                        .counters
                        .connect_failed
                        .fetch_add(1, Ordering::Relaxed);
                    let error = match failure {
                        Ok(Err(error)) => error,
                        _ => io::ErrorKind::TimedOut.into(),
                    };
                    crate::logging::warn_on_entry!(
                        self.backoff == INITIAL_BACKOFF,
                        %error,
                        "DNS syslog TCP connection failed"
                    );
                    self.failed();
                }
            }
        }
        let stream = self.stream.as_mut().expect("connected audit stream");
        match tokio::time::timeout(IO_TIMEOUT, stream.write_all(&batch.bytes)).await {
            Ok(Ok(())) => {
                self.admission
                    .counters
                    .submitted
                    .fetch_add(batch.events, Ordering::Relaxed);
                if self.backoff != INITIAL_BACKOFF {
                    tracing::info!("DNS syslog TCP delivery recovered");
                }
                self.backoff = INITIAL_BACKOFF;
                self.retry_at = None;
            }
            failure => {
                self.admission
                    .counters
                    .send_failed
                    .fetch_add(batch.events, Ordering::Relaxed);
                self.admission
                    .counters
                    .dropped
                    .fetch_add(batch.events, Ordering::Relaxed);
                let error = match failure {
                    Ok(Err(error)) => error,
                    _ => io::ErrorKind::TimedOut.into(),
                };
                crate::logging::warn_on_entry!(
                    self.backoff == INITIAL_BACKOFF,
                    %error,
                    "DNS syslog TCP batch write failed; discarding ambiguous batch"
                );
                self.failed();
            }
        }
        // A partial write may already have delivered full events. Never replay this batch.
        batch.clear();
    }
}

async fn flush<C: Connector>(
    transport: &mut Transport<C>,
    batch: &mut Batch,
    stopped: &mut oneshot::Receiver<()>,
) -> bool {
    tokio::select! {
        biased;
        _ = stopped => false,
        _ = transport.send(batch) => true,
    }
}

async fn run<C: Connector>(
    mut receiver: mpsc::Receiver<Entry>,
    mut stopped: oneshot::Receiver<()>,
    connector: C,
    admission: Arc<Admission>,
    identity: Identity,
    cee: bool,
) {
    let mut transport = Transport {
        connector,
        stream: None,
        backoff: INITIAL_BACKOFF,
        retry_at: None,
        admission: Arc::clone(&admission),
    };
    let instance = uuid::Uuid::new_v4().to_string();
    let mut sequence = 0u64;
    let mut batch = Batch::default();
    let mut deadline = None;
    loop {
        tokio::select! {
            biased;
            _ = &mut stopped => break,
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(|| Instant::now() + FLUSH_INTERVAL)), if deadline.is_some() => {
                if !flush(&mut transport, &mut batch, &mut stopped).await { break; }
                deadline = None;
            }
            entry = receiver.recv() => {
                let Some(entry) = entry else {
                    if batch.events != 0 { let _ = flush(&mut transport, &mut batch, &mut stopped).await; }
                    break;
                };
                sequence += 1;
                let id = format!("{instance}:{sequence}");
                let encoded = encode(&entry, &id).map_err(io::Error::other)
                    .and_then(|value| frame(&value, entry.completed, &identity, cee));
                drop(entry);
                let bytes = match encoded {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        admission.counters.invalid.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(%error, "DNS syslog event not encodable; dropped");
                        continue;
                    }
                };
                if batch.events != 0 && batch.bytes.len() + bytes.len() > BATCH_BYTES {
                    if !flush(&mut transport, &mut batch, &mut stopped).await {
                        admission.counters.dropped.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    deadline = None;
                }
                if batch.events == 0 { deadline = Some(Instant::now() + FLUSH_INTERVAL); }
                batch.push(bytes);
                if batch.bytes.len() >= BATCH_BYTES {
                    if !flush(&mut transport, &mut batch, &mut stopped).await { break; }
                    deadline = None;
                }
            }
        }
    }
    admission.stopped.store(true, Ordering::Release);
    receiver.close();
    admission
        .counters
        .dropped
        .fetch_add(batch.events, Ordering::Relaxed);
    while let Ok(entry) = receiver.try_recv() {
        admission.counters.dropped.fetch_add(1, Ordering::Relaxed);
        drop(entry);
    }
}

pub(crate) struct DnsAuditWorker {
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    admission: Arc<Admission>,
}

impl DnsAuditWorker {
    pub(crate) fn start(
        global: &honk_config::config::GlobalConfig,
    ) -> anyhow::Result<(DnsAudit, Option<Self>)> {
        if !global.syslog_dns_enabled {
            return Ok((DnsAudit::default(), None));
        }
        let target = global.syslog_addr.parse()?;
        let (audit, worker) = Self::with_connector(
            TcpConnector {
                target,
                mark: global.effective_so_mark(),
            },
            Identity::from_config(global),
            global.syslog_cee_enabled,
        );
        Ok((audit, Some(worker)))
    }

    pub(super) fn with_connector<C: Connector>(
        connector: C,
        identity: Identity,
        cee: bool,
    ) -> (DnsAudit, Self) {
        let (sender, receiver) = mpsc::channel(QUEUE_LEN);
        let (stop, stopped) = oneshot::channel();
        let admission = Arc::new(Admission::default());
        let task = tokio::spawn(run(
            receiver,
            stopped,
            connector,
            Arc::clone(&admission),
            identity,
            cee,
        ));
        (
            DnsAudit {
                sender: Some(sender),
                admission: Arc::clone(&admission),
            },
            Self {
                stop: Some(stop),
                task: Some(task),
                admission,
            },
        )
    }

    pub(crate) async fn shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(Duration::from_secs(1), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        self.admission.stopped.store(true, Ordering::Release);
        let counters = &self.admission.counters;
        tracing::info!(
            dropped = counters.dropped.load(Ordering::Relaxed),
            invalid = counters.invalid.load(Ordering::Relaxed),
            connect_failed = counters.connect_failed.load(Ordering::Relaxed),
            send_failed = counters.send_failed.load(Ordering::Relaxed),
            submitted = counters.submitted.load(Ordering::Relaxed),
            "DNS TCP syslog sender stopped"
        );
    }
}

impl Drop for DnsAuditWorker {
    fn drop(&mut self) {
        self.admission.stopped.store(true, Ordering::Release);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests;
