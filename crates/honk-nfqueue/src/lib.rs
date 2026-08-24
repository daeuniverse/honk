mod netlink;
mod packet;
mod queue;
mod rules;
mod verdict;

#[cfg(all(test, target_os = "linux"))]
mod kernel_tests;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub use packet::{PacketError, QueuedPacket, UdpTuple};
pub use rules::{CHAIN_NAME, CHAIN_PRIORITY, TABLE_NAME};
pub use verdict::{NF_ACCEPT, NF_DROP, VerdictError, VerdictGuard};

pub const QUEUE_NUM: u16 = 320;
pub const QUEUE_MAXLEN: u32 = 4096;
pub const COPY_RANGE: u32 = 65_535;
pub const SO_RCVBUF_SIZE: usize = 8 * 1024 * 1024;
pub const MAX_DATAGRAM_SIZE: usize = 128 * 1024;
pub const NFQUEUE_PENDING_MARK: u32 = 0x8000_0000;
pub const NFQUEUE_SIGNATURE_MARK: u32 = 0xc000_0000;
pub const NFQUEUE_TOKEN_MASK: u32 = 0x3fff_ffff;

#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    #[error("NFQUEUE netlink unavailable: {0}")]
    Queue(#[source] io::Error),
    #[error("NFQUEUE {QUEUE_NUM} is already bound")]
    QueueBusy,
}

/// Check fixed queue ownership before binding. The process-wide honk lock
/// reserves the nftables names; installation reclaims stale owned state.
pub fn preflight() -> Result<(), PreflightError> {
    queue::preflight().map_err(|error| match error {
        queue::QueueError::Busy => PreflightError::QueueBusy,
        queue::QueueError::Io(error) => PreflightError::Queue(error),
    })
}

pub type PacketCallback = Arc<dyn Fn(QueuedPacket, VerdictGuard) + Send + Sync + 'static>;
pub type FatalReceiver = tokio::sync::oneshot::Receiver<FatalError>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QueueStats {
    pub kernel_queue_depth: u64,
    pub kernel_dropped: u64,
    pub kernel_user_dropped: u64,
    pub held_packets: usize,
    pub held_peak: usize,
    pub socket_receive_buffer_bytes: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QueueLocalStats {
    pub held_packets: usize,
    pub held_peak: usize,
    pub socket_receive_buffer_bytes: usize,
}

fn parse_kernel_queue_stats(contents: &str) -> Option<(u64, u64, u64)> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let queue = fields.next()?.parse::<u16>().ok()?;
        let _peer_port = fields.next()?;
        let depth = fields.next()?.parse().ok()?;
        let _copy_mode = fields.next()?;
        let _copy_range = fields.next()?;
        let dropped = fields.next()?.parse().ok()?;
        let user_dropped = fields.next()?.parse().ok()?;
        (queue == QUEUE_NUM).then_some((depth, dropped, user_dropped))
    })
}

#[derive(Debug, thiserror::Error)]
pub enum FatalError {
    #[error("NFQUEUE receive lost packets with ENOBUFS")]
    Enobufs,
    #[error("NFQUEUE listener {operation} failed: {error}")]
    ListenerIo {
        operation: &'static str,
        error: String,
    },
    #[error("NFQUEUE datagram length {length} exceeds limit {limit}")]
    DatagramTooLarge { length: usize, limit: usize },
    #[error("NFQUEUE datagram length changed from {expected} to {actual}")]
    DatagramLengthChanged { expected: usize, actual: usize },
    #[error("NFQUEUE datagram was truncated")]
    DatagramTruncated,
    #[error("malformed NFQUEUE message: {error}")]
    MalformedMessage { error: String },
    #[error("unexpected netfilter netlink message type {message_type}")]
    UnexpectedMessage { message_type: u16 },
    #[error("packet arrived on unexpected NFQUEUE {queue}")]
    UnexpectedQueue { queue: u16 },
    #[error("NFQUEUE packet callback panicked")]
    CallbackPanicked,
    #[error("NFQUEUE listener exited unexpectedly")]
    ListenerExited,
    #[error("NFQUEUE listener thread panicked")]
    ListenerPanicked,
    #[error("NFQUEUE verdict socket failed: {error}")]
    VerdictSocket { error: String },
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("failed to bind and configure NFQUEUE: {0}")]
    Queue(String),
    #[error("failed to install NFQUEUE nftables ownership: {0}")]
    Rules(String),
    #[error("failed to spawn NFQUEUE listener: {0}")]
    ListenerThread(#[source] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    #[error("failed to remove NFQUEUE nftables ownership: {0}")]
    Rules(String),
}

pub struct NfqueueService {
    stop: Arc<AtomicBool>,
    listener: Option<std::thread::JoinHandle<()>>,
    socket: Option<Arc<queue::QueueSocket>>,
    rules: Option<rules::NftRuleset>,
    guards: Arc<verdict::GuardTracker>,
    socket_receive_buffer_bytes: Arc<AtomicUsize>,
    kernel_counters: Arc<parking_lot::Mutex<KernelCounterState>>,
    callback: PacketCallback,
    shutdown_complete: bool,
}

#[derive(Clone)]
pub struct QueueStatsReader {
    guards: Arc<verdict::GuardTracker>,
    socket_receive_buffer_bytes: Arc<AtomicUsize>,
    kernel_counters: Arc<parking_lot::Mutex<KernelCounterState>>,
}

#[derive(Default)]
struct KernelCounterState {
    generation: u64,
    last_dropped: u64,
    last_user_dropped: u64,
    total_dropped: u64,
    total_user_dropped: u64,
}

impl KernelCounterState {
    fn reset_instance(&mut self) {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("NFQUEUE instance generation overflow");
        self.last_dropped = 0;
        self.last_user_dropped = 0;
    }

    fn accumulate(
        &mut self,
        generation: u64,
        dropped: u64,
        user_dropped: u64,
    ) -> io::Result<(u64, u64)> {
        if generation != self.generation {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "NFQUEUE instance changed during statistics read",
            ));
        }
        self.total_dropped = self
            .total_dropped
            .saturating_add(dropped.checked_sub(self.last_dropped).unwrap_or(dropped));
        self.total_user_dropped = self.total_user_dropped.saturating_add(
            user_dropped
                .checked_sub(self.last_user_dropped)
                .unwrap_or(user_dropped),
        );
        self.last_dropped = dropped;
        self.last_user_dropped = user_dropped;
        Ok((self.total_dropped, self.total_user_dropped))
    }
}

impl QueueStatsReader {
    pub fn local_stats(&self) -> QueueLocalStats {
        QueueLocalStats {
            held_packets: self.guards.count(),
            held_peak: self.guards.peak(),
            socket_receive_buffer_bytes: self.socket_receive_buffer_bytes.load(Ordering::Relaxed),
        }
    }

    pub async fn stats(&self) -> io::Result<QueueStats> {
        let generation = self.kernel_counters.lock().generation;
        let contents = tokio::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue").await?;
        let (kernel_queue_depth, kernel_dropped, kernel_user_dropped) =
            parse_kernel_queue_stats(&contents).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "owned NFQUEUE status row is absent",
                )
            })?;
        let (kernel_dropped, kernel_user_dropped) = self.kernel_counters.lock().accumulate(
            generation,
            kernel_dropped,
            kernel_user_dropped,
        )?;
        let local = self.local_stats();
        Ok(QueueStats {
            kernel_queue_depth,
            kernel_dropped,
            kernel_user_dropped,
            held_packets: local.held_packets,
            held_peak: local.held_peak,
            socket_receive_buffer_bytes: local.socket_receive_buffer_bytes,
        })
    }
}

fn spawn_listener(
    socket: Arc<queue::QueueSocket>,
    stop: Arc<AtomicBool>,
    callback: PacketCallback,
    guards: Arc<verdict::GuardTracker>,
    fatal: Arc<FatalNotifier>,
) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("honk-nfqueue".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                queue::listen(socket, Arc::clone(&stop), callback, guards)
            }));
            match result {
                Ok(Ok(())) if stop.load(Ordering::Acquire) => {}
                Ok(Ok(())) => fatal.notify(FatalError::ListenerExited),
                Ok(Err(error)) => fatal.notify(error),
                Err(_) => fatal.notify(FatalError::ListenerPanicked),
            }
        })
}

impl NfqueueService {
    /// Binds the fixed queue before publishing the atomic nftables transaction.
    pub fn start(callback: PacketCallback) -> Result<(Self, FatalReceiver), StartError> {
        let (fatal, fatal_receiver) = fatal_channel();
        let socket = queue::QueueSocket::bind(Arc::clone(&fatal))
            .map_err(|error| StartError::Queue(error.to_string()))?;
        let mut rules =
            rules::NftRuleset::install().map_err(|error| StartError::Rules(error.to_string()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let guards = verdict::GuardTracker::new();
        let socket_receive_buffer_bytes = Arc::new(AtomicUsize::new(socket.receive_buffer_bytes()));
        let kernel_counters = Arc::new(parking_lot::Mutex::new(KernelCounterState::default()));

        let listener = match spawn_listener(
            Arc::clone(&socket),
            Arc::clone(&stop),
            Arc::clone(&callback),
            Arc::clone(&guards),
            Arc::clone(&fatal),
        ) {
            Ok(listener) => listener,
            Err(error) => {
                socket.mark_closed();
                let _ = rules.uninstall();
                return Err(StartError::ListenerThread(error));
            }
        };

        Ok((
            Self {
                stop,
                listener: Some(listener),
                socket: Some(socket),
                rules: Some(rules),
                guards,
                socket_receive_buffer_bytes,
                kernel_counters,
                callback,
                shutdown_complete: false,
            },
            fatal_receiver,
        ))
    }

    pub fn stats_reader(&self) -> QueueStatsReader {
        QueueStatsReader {
            guards: Arc::clone(&self.guards),
            socket_receive_buffer_bytes: Arc::clone(&self.socket_receive_buffer_bytes),
            kernel_counters: Arc::clone(&self.kernel_counters),
        }
    }

    /// Drop every skb owned by the old queue before rebinding it. Producers
    /// must already be fenced, and callers must drain their callback state.
    pub fn rebind(mut self) -> Result<(Self, FatalReceiver), StartError> {
        self.stop_listener();
        drop(self.socket.take());
        self.guards.wait_until_drained();

        let (fatal, fatal_receiver) = fatal_channel();
        let socket = queue::QueueSocket::bind(Arc::clone(&fatal))
            .map_err(|error| StartError::Queue(error.to_string()))?;
        self.socket_receive_buffer_bytes
            .store(socket.receive_buffer_bytes(), Ordering::Relaxed);
        self.kernel_counters.lock().reset_instance();
        let stop = Arc::new(AtomicBool::new(false));
        let listener = match spawn_listener(
            Arc::clone(&socket),
            Arc::clone(&stop),
            Arc::clone(&self.callback),
            Arc::clone(&self.guards),
            fatal,
        ) {
            Ok(listener) => listener,
            Err(error) => {
                socket.mark_closed();
                return Err(StartError::ListenerThread(error));
            }
        };
        self.stop = stop;
        self.listener = Some(listener);
        self.socket = Some(socket);
        Ok((self, fatal_receiver))
    }

    /// The caller must fence packet producers first; this waits for every
    /// dispatched guard, closes the queue, then deletes the wholly owned table.
    pub fn shutdown(mut self) -> Result<(), ShutdownError> {
        self.stop_listener();
        self.guards.wait_until_drained();
        self.close_queue();
        let result = self.remove_rules();
        self.shutdown_complete = true;
        result
    }

    fn stop_listener(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
    }

    fn close_queue(&mut self) {
        if let Some(socket) = self.socket.take() {
            socket.mark_closed();
            drop(socket);
        }
    }

    fn remove_rules(&mut self) -> Result<(), ShutdownError> {
        let Some(mut rules) = self.rules.take() else {
            return Ok(());
        };
        rules
            .uninstall()
            .map_err(|error| ShutdownError::Rules(error.to_string()))
    }
}

impl Drop for NfqueueService {
    fn drop(&mut self) {
        if self.shutdown_complete {
            return;
        }
        self.stop_listener();
        self.close_queue();
        // Only explicit shutdown proves producers are fenced; the unbound no-bypass rule
        // must remain fail-closed during unwinding.
    }
}

pub(crate) struct FatalNotifier {
    sender: parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<FatalError>>>,
}

impl FatalNotifier {
    pub(crate) fn notify(&self, error: FatalError) {
        let sender = self.sender.lock().take();
        if let Some(sender) = sender {
            let _ = sender.send(error);
        }
    }
}

pub(crate) fn fatal_channel() -> (Arc<FatalNotifier>, FatalReceiver) {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    (
        Arc::new(FatalNotifier {
            sender: parking_lot::Mutex::new(Some(sender)),
        }),
        receiver,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_owned_kernel_queue_stats() {
        let input = "319 10 1 2 65535 3 4 8\n320 20 17 2 65535 5 6 9\n";
        assert_eq!(super::parse_kernel_queue_stats(input), Some((17, 5, 6)));
    }

    #[test]
    fn local_stats_change_without_kernel_procfs() {
        let tracker = super::verdict::GuardTracker::new();
        let reader = super::QueueStatsReader {
            guards: std::sync::Arc::clone(&tracker),
            socket_receive_buffer_bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(
                4096,
            )),
            kernel_counters: std::sync::Arc::new(parking_lot::Mutex::new(
                super::KernelCounterState::default(),
            )),
        };
        let (socket, _peer, _fatal) = super::queue::QueueSocket::for_test();
        let guard = super::verdict::VerdictGuard::new(socket, 1, tracker);

        assert_eq!(
            reader.local_stats(),
            super::QueueLocalStats {
                held_packets: 1,
                held_peak: 1,
                socket_receive_buffer_bytes: 4096,
            }
        );
        drop(guard);
        assert_eq!(reader.local_stats().held_packets, 0);
        assert_eq!(reader.local_stats().held_peak, 1);
    }

    #[test]
    fn kernel_drop_counters_continue_across_queue_rebind() {
        let mut counters = super::KernelCounterState::default();
        assert_eq!(counters.accumulate(0, 5, 6).unwrap(), (5, 6));
        assert_eq!(counters.accumulate(0, 7, 9).unwrap(), (7, 9));

        counters.reset_instance();
        assert!(counters.accumulate(0, 8, 10).is_err());
        assert_eq!(counters.accumulate(1, 2, 1).unwrap(), (9, 10));
    }
}
