use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::proxy::{quic_carrier_error, quic_carrier_io_error};

use super::{QuicClient, now_secs};

/// A proxy-carrier QUIC stream as a single `AsyncRead + AsyncWrite` object.
///
/// Connection loss carries [`crate::proxy::NodeFailure`]; stream resets do not.
/// End-to-end QUIC users should use Quinn's streams directly.
///
/// Dropping the send half finishes the stream (sends FIN), which is what the
/// relay's half-close semantics rely on. The [`StreamDropGuard`] lets the
/// owning protocol track open-stream counts (for idle connection reaping)
/// without wrapping the stream again.
pub struct QuicBiStream {
    send: SendStream,
    recv: RecvStream,
    guard: StreamDropGuard,
}

/// Fires the registered callback when dropped. Lives inside
/// [`QuicBiStream`]; users that split the stream into its raw quinn halves
/// ([`QuicBiStream::into_parts`]) keep the guard for the same lifetime
/// accounting.
pub(crate) struct StreamDropGuard(Option<Box<dyn Fn() + Send + Sync>>);

impl Drop for StreamDropGuard {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

impl std::fmt::Debug for QuicBiStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicBiStream")
            .field("send", &self.send)
            .field("recv", &self.recv)
            .finish_non_exhaustive()
    }
}

impl QuicBiStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            guard: StreamDropGuard(None),
        }
    }

    /// Register a callback fired when this stream object is dropped.
    pub fn with_on_drop(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.guard.0 = Some(Box::new(f));
        self
    }

    /// Poll one cancellation-safe scatter write. `chunks` retains exactly the
    /// unsent suffix when progress is made.
    pub(crate) fn poll_write_chunks(
        &mut self,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        use std::future::Future;

        let result = std::pin::pin!(self.send.write_chunks(chunks)).poll(cx);
        result.map(|result| {
            result
                .map(|written| written.bytes)
                .map_err(|error| quic_carrier_io_error(io::Error::other(error)))
        })
    }

    /// Split into the raw quinn halves plus the drop guard (open-stream
    /// accounting) — for users that drive the halves separately, e.g. UDP
    /// session bridges.
    pub(crate) fn into_parts(self) -> (SendStream, RecvStream, StreamDropGuard) {
        (self.send, self.recv, self.guard)
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Fully-qualified calls: quinn's inherent `poll_read`/`poll_write`
        // methods (different error types) would shadow the trait methods.
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf).map_err(quic_carrier_io_error)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf).map_err(quic_carrier_io_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx).map_err(quic_carrier_io_error)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx).map_err(quic_carrier_io_error)
    }
}

// ---------------------------------------------------------------------------
// Shared skeletons for the TUIC / Juicity / Hysteria2 protocol handlers
// ---------------------------------------------------------------------------

/// Per-connection state shared by the QUIC proxy handlers: the activity
/// bookkeeping used by the dial retry skeleton and the idle reaper.
pub(crate) trait QuicConnState: Send + Sync + 'static {
    /// Record activity on the connection (resets the idle reaper).
    fn touch(&self);
    /// Counter of open streams/bridges on this connection.
    fn open_counter(&self) -> &Arc<AtomicUsize>;
    /// Include watchdog retirements from this connection in aggregate telemetry.
    fn enable_telemetry(&self);
}

/// TUIC-style exporter authentication (sing `clientHandshake`,
/// `client.go:197-214`): one uni stream carrying
/// `[version, 0x00, uuid(16), token(32)]` where
/// `token = TLS ExportKeyingMaterial(label = uuid, context = password, 32)`.
/// Juicity reuses the same frame with version 0x00 and keeps the stream
/// open (`finish = false`); TUIC finishes it right after the write.
///
/// There is no positive auth acknowledgement: a server that rejects the
/// credentials closes the connection, so the call waits a brief `grace`
/// period for that to surface as a dial error here instead of a stream
/// failure on the first proxied connection. Returns the auth stream.
pub(crate) async fn exporter_auth(
    conn: &Connection,
    uuid: &[u8; 16],
    password: &str,
    version: u8,
    finish: bool,
    grace: Duration,
) -> anyhow::Result<SendStream> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|e| anyhow!("QUIC exporter auth: TLS keying material export failed: {e:?}"))?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.push(version);
    auth.push(0x00); // CMD_AUTHENTICATE
    auth.extend_from_slice(uuid);
    auth.extend_from_slice(&token);
    let mut stream = conn
        .open_uni()
        .await
        .context("QUIC exporter auth: open authenticate stream")?;
    stream
        .write_all(&auth)
        .await
        .context("QUIC exporter auth: send authenticate")?;
    if finish {
        stream
            .finish()
            .context("QUIC exporter auth: finish authenticate stream")?;
    }
    tokio::select! {
        e = conn.closed() => Err(anyhow::Error::new(e).context("QUIC exporter auth: connection closed during authentication")),
        _ = tokio::time::sleep(grace) => Ok(stream),
    }
}

/// Per-tick callback for [`spawn_conn_reaper`] (TUIC's heartbeat datagram);
/// returning false ends the reaper loop.
type ReaperTick = Box<dyn Fn(&Connection) -> bool + Send + 'static>;

/// Spawn the idle-connection reaper shared by the QUIC protocol handlers:
/// every `interval`, close the connection when the owning protocol state was
/// dropped ("state dropped") or when it has had no open streams/bridges for
/// `idle_timeout` ("idle"). `on_tick` runs after the liveness checks (TUIC's
/// heartbeat datagram); returning false ends the loop.
pub(crate) fn spawn_conn_reaper(
    conn: Connection,
    open: Weak<AtomicUsize>,
    last_activity: Weak<AtomicU64>,
    interval: Duration,
    idle_timeout: Duration,
    on_tick: Option<ReaperTick>,
) {
    let _ = crate::runtime::spawn_owned(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if conn.close_reason().is_some() {
                break;
            }
            let (Some(open), Some(last)) = (open.upgrade(), last_activity.upgrade()) else {
                // Protocol state dropped: nothing can use this connection.
                conn.close(VarInt::from_u32(0), b"state dropped");
                break;
            };
            let idle = now_secs().saturating_sub(last.load(Ordering::Relaxed));
            if open.load(Ordering::Relaxed) == 0 && idle > idle_timeout.as_secs() {
                conn.close(VarInt::from_u32(0), b"idle");
                break;
            }
            if let Some(on_tick) = &on_tick
                && !on_tick(&conn)
            {
                break;
            }
        }
    });
}

/// Shared TCP-over-QUIC dial skeleton (TUIC/Juicity/Hysteria2). The returned
/// stream decrements the connection's open counter on drop.
pub(crate) async fn dial_quic_stream<S, Connect, Fut, Make, MakeFut>(
    client: &QuicClient<S>,
    connect: Connect,
    connect_timeout: Duration,
    make: Make,
    retryable: impl Fn(&anyhow::Error) -> bool,
    proto: &'static str,
) -> anyhow::Result<QuicBiStream>
where
    S: QuicConnState,
    Connect: Fn(Duration) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<(Connection, Arc<S>)>>,
    Make: Fn(Connection) -> MakeFut,
    MakeFut: std::future::Future<Output = anyhow::Result<(SendStream, RecvStream)>>,
{
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..2 {
        let (conn, state) = connect(connect_timeout).await?;
        state.touch();
        let observation = crate::session::ObservedSessionOpen::start();
        match make(conn.clone()).await.map_err(quic_carrier_error) {
            Ok((send, recv)) => {
                observation.finish(crate::runtime::flow_observation::SessionEvent::OpenSucceeded);
                let open = Arc::clone(state.open_counter());
                open.fetch_add(1, Ordering::Relaxed);
                let stream_state = Arc::clone(&state);
                let stream = QuicBiStream::new(send, recv).with_on_drop(move || {
                    open.fetch_sub(1, Ordering::Relaxed);
                    let _state_kept_alive_under_this_stream = &stream_state;
                });
                return Ok(stream);
            }
            Err(e) if retryable(&e) => {
                observation.finish(crate::runtime::flow_observation::SessionEvent::OpenFailed);
                debug!("{proto}: stream open failed (attempt {attempt}): {e}");
                client.invalidate(&conn).await;
                last_err = Some(e);
            }
            Err(e) => {
                observation.finish(crate::runtime::flow_observation::SessionEvent::OpenRefused);
                return Err(e);
            }
        }
    }
    Err(last_err.expect("loop runs at least once"))
}
