//! Bounded connected DNS-over-UDP exchange pool.
//!
//! A single generation-owned socket owns its receive loop. Requests receive a
//! pool-local DNS ID and are demultiplexed by ID plus question, so a delayed
//! packet cannot be delivered to a different question after ID reuse.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use honk_ebpf_common::DAE_BYPASS_MARK;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as TokioMutex, oneshot};

use super::owned_task::OwnedTask;

const MAX_PENDING: usize = 1024;
const ID_QUARANTINE: Duration = Duration::from_secs(3);
const ID_BITMAP_WORDS: usize = (u16::MAX as usize + 1) / u64::BITS as usize;

struct Pending {
    nonce: u64,
    question: Vec<u8>,
    original_id: [u8; 2],
    reply: oneshot::Sender<Vec<u8>>,
}

struct State {
    closed: bool,
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
        honk_outbound::util::set_mark_best_effort(&socket, DAE_BYPASS_MARK)?;
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
        self.socket.send(&wire).await?;
        if let Some(reporter) = reporter {
            reporter.setup_succeeded();
            reporter.tx(query.len() as u64);
        }
        match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => anyhow::bail!("UDP DNS receive loop stopped"),
            Err(_) => anyhow::bail!("UDP DNS query timed out after {:?}", self.timeout),
        }
    }

    async fn receive_loop(pool: Weak<Self>, socket: Arc<UdpSocket>) {
        let mut buffer = vec![0; 65535];
        loop {
            let Ok(Ok(length)) =
                tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut buffer)).await
            else {
                if pool.strong_count() == 0 {
                    break;
                }
                continue;
            };
            if length < 12 {
                continue;
            }
            let Some(pool) = pool.upgrade() else {
                break;
            };
            let id = u16::from_be_bytes([buffer[0], buffer[1]]);
            let pending = {
                let mut state = pool.state.lock();
                let matches = Self::question_end(&buffer[..length]).is_ok_and(|end| {
                    state
                        .pending
                        .get(&id)
                        .is_some_and(|pending| pending.question == buffer[12..end])
                });
                if matches {
                    let pending = state.pending.remove(&id);
                    if pending.is_some() {
                        Self::retire_id(&mut state, id);
                    }
                    pending
                } else {
                    None
                }
            };
            if let Some(pending) = pending {
                let mut response = buffer[..length].to_vec();
                response[..2].copy_from_slice(&pending.original_id);
                let _ = pending.reply.send(response);
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

    #[tokio::test]
    async fn cancelled_exchange_unregisters_and_quarantines_pool_id() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let pool = UdpPool::new(address, Duration::from_secs(60))
            .await
            .unwrap();
        let exchange_pool = Arc::clone(&pool);
        let exchange =
            tokio::spawn(async move { exchange_pool.exchange(&query(0x1234), None).await });
        let mut buffer = [0_u8; 512];
        let (length, _) = server.recv_from(&mut buffer).await.unwrap();
        assert!(length >= 2);
        let id = u16::from_be_bytes([buffer[0], buffer[1]]);

        exchange.abort();
        assert!(exchange.await.unwrap_err().is_cancelled());

        {
            let state = pool.state.lock();
            assert!(state.pending.is_empty());
            assert!(UdpPool::is_retired(&state, id));
        }
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
