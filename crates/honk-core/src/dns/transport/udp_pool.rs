//! Bounded connected DNS-over-UDP exchange pool.
//!
//! A single generation-owned socket owns its receive loop. Requests receive a
//! pool-local DNS ID and are demultiplexed by ID plus question, so a delayed
//! packet cannot be delivered to a different question after ID reuse.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use honk_outbound::SharedError;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as TokioMutex, oneshot};

use super::owned_task::OwnedTask;

#[cfg(target_os = "linux")]
mod error_queue;

const MAX_PENDING: usize = 1024;
const ID_QUARANTINE: Duration = Duration::from_secs(3);
const ID_BITMAP_WORDS: usize = (u16::MAX as usize + 1) / u64::BITS as usize;

struct Pending {
    nonce: u64,
    question: Vec<u8>,
    original_id: [u8; 2],
    reply: oneshot::Sender<Result<Vec<u8>, SharedError>>,
}

enum Received {
    Datagram(usize),
    #[cfg(target_os = "linux")]
    ErrorQuote(usize, Option<io::Error>),
}

fn socket_failed(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EBADF | libc::ENOTSOCK | libc::EINVAL | libc::EIO)
    )
}

struct State {
    closed: bool,
    stopped: Option<SharedError>,
    next_nonce: u64,
    pending: HashMap<u16, Pending>,
    retired: VecDeque<(Instant, u16)>,
    retired_ids: [u64; ID_BITMAP_WORDS],
}

/// One bounded, connected socket for a direct UDP upstream.
pub struct UdpPool {
    socket: Arc<UdpSocket>,
    state: Mutex<State>,
    receive_task: TokioMutex<Option<OwnedTask>>,
    timeout: Duration,
}

struct PendingGuard<'a> {
    pool: &'a UdpPool,
    id: u16,
    nonce: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.pool.state.lock();
        if state
            .pending
            .get(&self.id)
            .is_some_and(|pending| pending.nonce == self.nonce)
        {
            state.pending.remove(&self.id);
            UdpPool::retire_id(&mut state, self.id);
        }
    }
}

impl UdpPool {
    pub async fn new(address: SocketAddr, timeout: Duration) -> anyhow::Result<Arc<Self>> {
        Self::new_tracked(address, timeout, Arc::new(AtomicUsize::new(0))).await
    }

    pub(crate) async fn new_tracked(
        address: SocketAddr,
        timeout: Duration,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        let domain = if address.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        #[cfg(target_os = "linux")]
        honk_outbound::util::set_mark_best_effort(&socket, honk_outbound::util::bypass_mark())?;
        #[cfg(target_os = "linux")]
        error_queue::enable(&socket, address.is_ipv6())?;
        let unspecified = if address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        socket.bind(&SocketAddr::new(unspecified, 0).into())?;
        let socket = Arc::new(UdpSocket::from_std(socket.into())?);
        socket.connect(address).await?;
        let pool = Arc::new(Self {
            socket: Arc::clone(&socket),
            state: Mutex::new(State {
                closed: false,
                stopped: None,
                next_nonce: 0,
                pending: HashMap::new(),
                retired: VecDeque::new(),
                retired_ids: [0; ID_BITMAP_WORDS],
            }),
            receive_task: TokioMutex::new(None),
            timeout,
        });
        let receive_task = OwnedTask::spawn(
            Self::receive_loop(Arc::downgrade(&pool), socket),
            active_tasks,
        );
        pool.receive_task.lock().await.replace(receive_task);
        Ok(pool)
    }

    /// Closed or failed sockets cannot serve a new exchange.
    pub(crate) fn is_stopped(&self) -> bool {
        let state = self.state.lock();
        state.closed || state.stopped.is_some()
    }

    pub(crate) async fn close(&self) {
        {
            let mut state = self.state.lock();
            state.closed = true;
            state.pending.clear();
        }
        let receive_task = self.receive_task.lock().await.take();
        if let Some(receive_task) = receive_task {
            receive_task.shutdown(Duration::ZERO).await;
        }
    }

    pub async fn exchange(
        &self,
        query: &[u8],
        reporter: Option<&honk_outbound::group::ScoreReporter>,
    ) -> anyhow::Result<Vec<u8>> {
        if query.len() < 12 {
            anyhow::bail!("malformed DNS query");
        }
        let original_id = [query[0], query[1]];
        let question = query[12..Self::question_end(query)?].to_vec();
        let (reply, receiver) = oneshot::channel();
        let (id, nonce) = {
            let mut state = self.state.lock();
            if state.closed {
                anyhow::bail!("UDP DNS exchange pool is closed");
            }
            if let Some(failure) = &state.stopped {
                return Err(anyhow::Error::new(failure.clone()));
            }
            Self::purge_retired(&mut state);
            if state.pending.len() >= MAX_PENDING {
                anyhow::bail!("UDP DNS exchange pool saturated");
            }
            let id = Self::allocate_id(&state)
                .ok_or_else(|| anyhow::anyhow!("UDP DNS IDs exhausted"))?;
            let nonce = state
                .next_nonce
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("UDP DNS registration nonce exhausted"))?;
            state.next_nonce = nonce;
            state.pending.insert(
                id,
                Pending {
                    nonce,
                    question,
                    original_id,
                    reply,
                },
            );
            (id, nonce)
        };
        let _pending = PendingGuard {
            pool: self,
            id,
            nonce,
        };
        let mut wire = query.to_vec();
        wire[..2].copy_from_slice(&id.to_be_bytes());
        tokio::time::timeout(self.timeout, async {
            self.socket.send(&wire).await?;
            if let Some(reporter) = reporter {
                reporter.setup_succeeded();
                reporter.tx(query.len() as u64);
            }
            Self::received_reply(receiver.await)
        })
        .await
        .map_err(|_| anyhow::anyhow!("UDP DNS query timed out after {:?}", self.timeout))?
    }

    fn received_reply(
        reply: Result<Result<Vec<u8>, SharedError>, oneshot::error::RecvError>,
    ) -> anyhow::Result<Vec<u8>> {
        match reply {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(anyhow::Error::new(error)),
            Err(_) => anyhow::bail!("UDP DNS receive loop stopped"),
        }
    }

    fn stop(&self, error: io::Error) {
        let failure =
            SharedError::fanout(anyhow::Error::new(error).context("UDP DNS receive failed"));
        let pending = {
            let mut state = self.state.lock();
            state.stopped.get_or_insert_with(|| failure.clone());
            let pending = std::mem::take(&mut state.pending);
            for id in pending.keys() {
                Self::retire_id(&mut state, *id);
            }
            pending
        };
        for pending in pending.into_values() {
            let _ = pending.reply.send(Err(failure.clone()));
        }
    }

    fn take_pending(&self, wire: &[u8]) -> Option<Pending> {
        let end = Self::question_end(wire).ok()?;
        let id = u16::from_be_bytes([wire[0], wire[1]]);
        let mut state = self.state.lock();
        if state.pending.get(&id)?.question != wire[12..end] {
            return None;
        }
        let pending = state.pending.remove(&id);
        Self::retire_id(&mut state, id);
        pending
    }

    async fn receive_loop(pool: Weak<Self>, socket: Arc<UdpSocket>) {
        let mut buffer = vec![0; 65535];
        #[cfg(target_os = "linux")]
        let mut quote = [0; 512];
        loop {
            let receive = async {
                #[cfg(target_os = "linux")]
                {
                    tokio::select! {
                        datagram = error_queue::receive_datagram(&socket, &mut buffer) => datagram.map(Received::Datagram),
                        error = error_queue::receive(&socket, &mut quote) => error.map(|(length, error)| Received::ErrorQuote(length, error)),
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    socket.recv(&mut buffer).await.map(Received::Datagram)
                }
            };
            let event = tokio::time::timeout(Duration::from_secs(1), receive).await;
            let Some(pool) = pool.upgrade() else {
                break;
            };
            if pool.is_stopped() {
                break;
            }
            match event {
                Err(_) => {}
                Ok(Ok(Received::Datagram(length))) => {
                    if let Some(pending) = pool.take_pending(&buffer[..length]) {
                        let mut response = buffer[..length].to_vec();
                        response[..2].copy_from_slice(&pending.original_id);
                        let _ = pending.reply.send(Ok(response));
                    }
                }
                #[cfg(target_os = "linux")]
                Ok(Ok(Received::ErrorQuote(length, error))) => {
                    if let Some(error) = error
                        && let Some(pending) = pool.take_pending(&quote[..length])
                    {
                        let failure = SharedError::new(
                            anyhow::Error::new(error).context("UDP DNS receive failed"),
                        );
                        let _ = pending.reply.send(Err(failure));
                    }
                    tokio::task::yield_now().await;
                }
                Ok(Err(error)) if socket_failed(&error) => {
                    pool.stop(error);
                    break;
                }
                Ok(Err(_)) => {
                    // recv may report a delayed packet error without its quote. The
                    // error-queue branch owns attribution; no pending query is removed.
                    tokio::task::yield_now().await;
                }
            }
        }
    }

    fn purge_retired(state: &mut State) {
        let now = Instant::now();
        while state
            .retired
            .front()
            .is_some_and(|(until, _)| *until <= now)
        {
            if let Some((_, id)) = state.retired.pop_front() {
                Self::set_retired(state, id, false);
            }
        }
    }
    fn retire_id(state: &mut State, id: u16) {
        Self::set_retired(state, id, true);
        state
            .retired
            .push_back((Instant::now() + ID_QUARANTINE, id));
    }
    fn is_retired(state: &State, id: u16) -> bool {
        let id = usize::from(id);
        state.retired_ids[id / u64::BITS as usize] & (1u64 << (id % u64::BITS as usize)) != 0
    }
    fn set_retired(state: &mut State, id: u16, retired: bool) {
        let id = usize::from(id);
        let word = &mut state.retired_ids[id / u64::BITS as usize];
        let mask = 1u64 << (id % u64::BITS as usize);
        if retired {
            *word |= mask;
        } else {
            *word &= !mask;
        }
    }
    fn question_end(wire: &[u8]) -> anyhow::Result<usize> {
        if wire.len() < 17 {
            anyhow::bail!("malformed DNS question");
        }
        let mut index = 12;
        loop {
            let label_len = *wire
                .get(index)
                .ok_or_else(|| anyhow::anyhow!("malformed DNS name"))?
                as usize;
            index += 1;
            if label_len == 0 {
                break;
            }
            if label_len > 63 || index + label_len > wire.len() {
                anyhow::bail!("malformed DNS name");
            }
            index += label_len;
        }
        if index + 4 > wire.len() {
            anyhow::bail!("malformed DNS question");
        }
        Ok(index + 4)
    }
    fn allocate_id(state: &State) -> Option<u16> {
        Self::allocate_id_from(state, rand::random())
    }

    fn allocate_id_from(state: &State, start: u16) -> Option<u16> {
        for offset in 0..=u16::MAX {
            let id = start.wrapping_add(offset);
            if !state.pending.contains_key(&id) && !Self::is_retired(state, id) {
                return Some(id);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(transaction_id: u16) -> Vec<u8> {
        let mut query = transaction_id.to_be_bytes().to_vec();
        query.extend_from_slice(&[
            0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ]);
        query
    }

    #[tokio::test]
    async fn oversized_query_returns_the_send_error_without_waiting_for_reply() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pool = UdpPool::new(server.local_addr().unwrap(), Duration::from_secs(5))
            .await
            .unwrap();
        let mut request = query(0x1234);
        request[10..12].copy_from_slice(&1u16.to_be_bytes());
        request.extend_from_slice(&[0, 0, 41, 0xff, 0xff, 0, 0, 0, 0]);
        let padding = u16::MAX as usize - request.len() - 6;
        request.extend_from_slice(&((padding + 4) as u16).to_be_bytes());
        request.extend_from_slice(&12u16.to_be_bytes());
        request.extend_from_slice(&(padding as u16).to_be_bytes());
        request.resize(u16::MAX as usize, 0);
        let error = tokio::time::timeout(Duration::from_secs(1), pool.exchange(&request, None))
            .await
            .expect("a synchronous send refusal must not wait for a response")
            .unwrap_err();
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.raw_os_error() == Some(libc::EMSGSIZE))
        }));
        pool.close().await;
    }

    #[tokio::test]
    async fn successful_exchange_quarantines_pool_id() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let (first_id_tx, first_id_rx) = oneshot::channel();
        let responder = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (first_len, first_peer) = server.recv_from(&mut buffer).await.unwrap();
            let first_id = u16::from_be_bytes([buffer[0], buffer[1]]);
            let _ = first_id_tx.send(first_id);
            let mut first_response = buffer[..first_len].to_vec();
            first_response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            server.send_to(&first_response, first_peer).await.unwrap();

            let (second_len, second_peer) = server.recv_from(&mut buffer).await.unwrap();
            let mut second_response = buffer[..second_len].to_vec();
            second_response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            server.send_to(&second_response, second_peer).await.unwrap();
        });
        let pool = UdpPool::new(address, Duration::from_secs(1)).await.unwrap();

        pool.exchange(&query(0x1234), None).await.unwrap();
        let first_id = first_id_rx.await.unwrap();
        {
            let state = pool.state.lock();
            assert!(UdpPool::is_retired(&state, first_id));
            assert_ne!(UdpPool::allocate_id_from(&state, first_id), Some(first_id));
        }
        pool.exchange(&query(0x5678), None).await.unwrap();

        pool.close().await;
        responder.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn refused_peer_fails_promptly_and_recovers_without_socket_replacement() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let closed = UdpSocket::bind(bind).await.unwrap();
            let address = closed.local_addr().unwrap();
            drop(closed);
            let pool = UdpPool::new(address, Duration::from_secs(5)).await.unwrap();
            let local = pool.socket.local_addr().unwrap();
            for attempt in 0..9 {
                let error = tokio::time::timeout(
                    Duration::from_secs(1),
                    pool.exchange(&query(0x1234), None),
                )
                .await
                .unwrap_or_else(|_| panic!("{bind} refusal {attempt} waited for timeout"))
                .unwrap_err();
                assert!(error.chain().any(|cause| {
                    cause
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.raw_os_error() == Some(libc::ECONNREFUSED))
                }));
            }
            let server = UdpSocket::bind(address).await.unwrap();
            let respond = async {
                let mut wire = [0; 512];
                let (length, peer) = server.recv_from(&mut wire).await.unwrap();
                assert_eq!(peer, local);
                wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
                server.send_to(&wire[..length], peer).await.unwrap();
            };
            let request = query(0x5678);
            let (response, ()) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(pool.exchange(&request, None), respond)
            })
            .await
            .unwrap();
            assert_eq!(&response.unwrap()[..2], &0x5678_u16.to_be_bytes());
            pool.close().await;
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn packet_error_does_not_fail_another_pending_query() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = server.local_addr().unwrap();
            let pool = UdpPool::new(address, Duration::from_secs(3)).await.unwrap();
            let first_query = query(0x1234);
            let second_query = query(0x5678);
            let mut first = Box::pin(pool.exchange(&first_query, None));
            let mut second = Box::pin(pool.exchange(&second_query, None));
            let mut first_wire = [0; 512];
            let (first_len, _) = tokio::select! {
                reply = &mut first => panic!("first query ended before its peer received it: {reply:?}"),
                packet = server.recv_from(&mut first_wire) => packet.unwrap(),
            };
            let mut second_wire = [0; 512];
            let (second_len, second_peer) = tokio::select! {
                reply = &mut second => panic!("second query ended before its peer received it: {reply:?}"),
                packet = server.recv_from(&mut second_wire) => packet.unwrap(),
            };
            drop(server);
            // Produce a real ICMP quote for the first wire ID while both queries wait.
            pool.socket.send(&first_wire[..first_len]).await.unwrap();
            first.await.unwrap_err();
            let recovered = UdpSocket::bind(address).await.unwrap();
            second_wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            recovered.send_to(&second_wire[..second_len], second_peer).await.unwrap();
            let response = second.await.expect("unrelated pending query must retain its response");
            assert_eq!(&response[..2], &0x5678_u16.to_be_bytes());
            pool.close().await;
        }).await.expect("packet-local error exchange stalled");
    }

    #[tokio::test]
    async fn fatal_socket_error_fails_all_waiters_and_future_queries() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pool = UdpPool::new(server.local_addr().unwrap(), Duration::from_secs(5))
            .await
            .unwrap();
        let first_query = query(0x1234);
        let second_query = query(0x5678);
        let mut first = Box::pin(pool.exchange(&first_query, None));
        let mut second = Box::pin(pool.exchange(&second_query, None));
        assert!(futures::poll!(first.as_mut()).is_pending());
        assert!(futures::poll!(second.as_mut()).is_pending());
        pool.stop(io::Error::from_raw_os_error(libc::EBADF));
        for error in [
            first.await.unwrap_err(),
            second.await.unwrap_err(),
            pool.exchange(&query(1), None).await.unwrap_err(),
        ] {
            assert!(error.chain().any(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.raw_os_error() == Some(libc::EBADF))
            }));
        }
        pool.close().await;
    }

    #[tokio::test]
    async fn cancelled_exchange_rejects_delayed_wire_response() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let pool = UdpPool::new(address, Duration::from_secs(60))
            .await
            .unwrap();

        let first_pool = Arc::clone(&pool);
        let first = tokio::spawn(async move { first_pool.exchange(&query(0x1234), None).await });
        let mut first_wire = [0_u8; 512];
        let (first_len, first_peer) = server.recv_from(&mut first_wire).await.unwrap();
        let first_id = u16::from_be_bytes(first_wire[..2].try_into().unwrap());
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        {
            let state = pool.state.lock();
            assert!(!state.pending.contains_key(&first_id));
            assert!(UdpPool::is_retired(&state, first_id));
        }

        let second_pool = Arc::clone(&pool);
        let mut second =
            tokio::spawn(async move { second_pool.exchange(&query(0x5678), None).await });
        let mut second_wire = [0_u8; 512];
        let (second_len, second_peer) = server.recv_from(&mut second_wire).await.unwrap();
        assert_ne!(
            u16::from_be_bytes(second_wire[..2].try_into().unwrap()),
            first_id
        );

        first_wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        server
            .send_to(&first_wire[..first_len], first_peer)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut second)
                .await
                .is_err(),
            "a delayed response for the cancelled wire ID completed its successor"
        );

        second_wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        server
            .send_to(&second_wire[..second_len], second_peer)
            .await
            .unwrap();
        let response = second.await.unwrap().unwrap();
        assert_eq!(&response[..2], &0x5678_u16.to_be_bytes());
        pool.close().await;
    }

    #[tokio::test]
    async fn close_wakes_pending_exchange_and_joins_receive_task() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let (received, received_rx) = oneshot::channel();
        let responder = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            server.recv_from(&mut buffer).await.unwrap();
            let _ = received.send(());
        });
        let active = Arc::new(AtomicUsize::new(0));
        let pool = UdpPool::new_tracked(address, Duration::from_secs(60), Arc::clone(&active))
            .await
            .unwrap();
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 1);
        let exchange_pool = Arc::clone(&pool);
        let exchange =
            tokio::spawn(async move { exchange_pool.exchange(&query(0x1234), None).await });
        received_rx.await.unwrap();

        pool.close().await;

        let error = tokio::time::timeout(Duration::from_secs(1), exchange)
            .await
            .expect("pending exchange did not wake during close")
            .unwrap()
            .expect_err("closed receive task cannot answer a pending exchange");
        assert!(error.to_string().contains("receive loop stopped"));
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(
            pool.exchange(&query(0x5678), None,)
                .await
                .expect_err("closed pool rejects exchanges")
                .to_string()
                .contains("closed")
        );
        responder.await.unwrap();
    }

    #[test]
    fn retired_id_bitmap_tracks_expiry_without_history_scans() {
        let mut state = State {
            closed: false,
            stopped: None,
            next_nonce: 0,
            pending: HashMap::new(),
            retired: VecDeque::new(),
            retired_ids: [0; ID_BITMAP_WORDS],
        };
        for id in 0..32_768 {
            UdpPool::retire_id(&mut state, id);
        }

        assert!(UdpPool::is_retired(&state, 0));
        assert!(UdpPool::is_retired(&state, 32_767));
        assert_eq!(UdpPool::allocate_id_from(&state, 0), Some(32_768));

        state.retired.front_mut().unwrap().0 = Instant::now() - Duration::from_secs(1);
        UdpPool::purge_retired(&mut state);
        assert!(!UdpPool::is_retired(&state, 0));
    }
}
