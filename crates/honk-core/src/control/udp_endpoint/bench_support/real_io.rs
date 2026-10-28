//! Real-I/O harness for `benches/udp_io.rs`.
//!
//! Unlike the synchronous helpers in the parent module, this drives the
//! production endpoint driver end to end: `fast_path_enqueue_at` -> driver
//! `send_one` -> transport -> peer echo -> receive loop (or source receiver)
//! -> loopback reply socket -> client socket. The transport is injected, so
//! a new source shape adds one `install_*` constructor and no new plumbing.

use super::super::driver::UdpDriverHandle;
use super::super::{
    EndpointReservation, ReplySocket, ReplySocketFd, ScopeId, UdpEndpoint, UdpEndpointPool,
    UdpInitLease, UdpReplySocketFactory, queue_now,
};
use crate::stats::StatsManager;
use honk_outbound::alive::{AliveDialerSet, IpVersion};
use honk_outbound::proxy::PacketTransport;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

mod source;
pub use source::Backend;

const POOL_CAPACITY: usize = 16;
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const FIRST_PAYLOAD: &[u8] = b"first";
const FLOW_NODE: uuid::Uuid = uuid::Uuid::from_u128(1);

/// Reply sockets are pre-bound loopback sockets handed out by clone: the
/// reply source address is the destination address, as with production
/// anyfrom sockets.
#[derive(Debug)]
struct BoundReplies(HashMap<SocketAddr, std::net::UdpSocket>);

impl UdpReplySocketFactory for BoundReplies {
    fn create(&self, scope: ScopeId, source: SocketAddr) -> io::Result<ReplySocketFd> {
        if scope != ScopeId::HOST {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unreserved bench scope",
            ));
        }
        let socket = self
            .0
            .get(&source)
            .ok_or_else(|| io::Error::other("unreserved reply source"))?
            .try_clone()?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket).map(ReplySocketFd::Kernel)
    }
}

/// Outcome of one steady-state enqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueue {
    Accepted,
    QueueFull,
    Rejected,
}

pub struct IoHarness {
    pool: Arc<UdpEndpointPool>,
    stats: Arc<StatsManager>,
    alive: Arc<AliveDialerSet>,
    client: UdpSocket,
    client_addr: SocketAddr,
    targets: Vec<SocketAddr>,
    source: Option<source::SourceRuntime>,
}

impl IoHarness {
    /// Binds a loopback client and `destinations` loopback target addresses.
    /// Must run inside the Tokio runtime that will drive the traffic.
    pub async fn new(destinations: usize) -> io::Result<Self> {
        let mut bound = HashMap::new();
        let mut targets = Vec::new();
        for _ in 0..destinations {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let address = socket.local_addr()?;
            bound.insert(address, socket);
            targets.push(address);
        }
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        Ok(Self {
            pool: Arc::new(UdpEndpointPool::with_reply_socket_factory(
                POOL_CAPACITY,
                Arc::new(BoundReplies(bound)),
            )),
            stats: Arc::new(StatsManager::new()),
            alive: Arc::new(AliveDialerSet::new()),
            client_addr: client.local_addr()?,
            client,
            targets,
            source: None,
        })
    }

    /// The client socket that receives every reply.
    pub fn client(&self) -> &UdpSocket {
        &self.client
    }

    pub fn target(&self, destination: usize) -> SocketAddr {
        self.targets[destination]
    }

    /// Ordinary per-flow endpoint over an injected transport. The first
    /// datagram is sent through the driver and its reply is consumed, so the
    /// flow is Ready and idle when this returns.
    pub async fn install_flow(
        &self,
        destination: usize,
        transport: Arc<dyn PacketTransport>,
    ) -> io::Result<()> {
        let target = self.targets[destination];
        let lease = self.reserve(target, FLOW_NODE)?;
        let endpoint = Arc::new(UdpEndpoint::new_scored(
            transport,
            target,
            false,
            FLOW_NODE,
            IpVersion::V4,
            None,
        ));
        let reply = Arc::new(self.pool.create_reply_socket(lease.scope(), target)?);
        self.start(lease, endpoint, target, reply).await
    }

    /// Production steady-state entry: the listener's Ready fast path.
    pub fn enqueue(&self, destination: usize, payload: &[u8]) -> Enqueue {
        match self.pool.fast_path_enqueue_at(
            honk_datapath::ScopeId::HOST,
            self.client_addr,
            self.targets[destination],
            payload,
            None,
            queue_now(),
            &self.stats,
        ) {
            Some(EndpointReservation::Enqueued) => Enqueue::Accepted,
            Some(EndpointReservation::QueueFull) => Enqueue::QueueFull,
            _ => Enqueue::Rejected,
        }
    }

    fn reserve(&self, target: SocketAddr, node_id: uuid::Uuid) -> io::Result<UdpInitLease> {
        let slow = Arc::new(Semaphore::new(1))
            .try_acquire_owned()
            .map_err(io::Error::other)?;
        let lease = match self.pool.reserve_or_enqueue_at(
            honk_datapath::ScopeId::HOST,
            self.client_addr,
            target,
            FIRST_PAYLOAD,
            None,
            crate::ebpf::UdpFlowOwner::new(0, None).expect("benchmark UDP owner"),
            self.pool.initialization_epoch(),
            slow,
            queue_now(),
            &self.stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => return Err(io::Error::other("destination already has a mapping")),
        };
        if !lease.bind_selected_node(node_id) {
            return Err(io::Error::other("lease cancelled"));
        }
        Ok(lease)
    }

    /// Production Ready commit: driver ready -> commit -> first send -> ack,
    /// then the echoed first datagram is drained from the client socket.
    async fn start(
        &self,
        mut lease: UdpInitLease,
        endpoint: Arc<UdpEndpoint>,
        target: SocketAddr,
        reply: Arc<ReplySocket>,
    ) -> io::Result<()> {
        let queue = lease
            .take_queue_receiver()
            .ok_or_else(|| io::Error::other("lease has no queue"))?;
        let mut driver: UdpDriverHandle = self.pool.spawn_driver(
            honk_datapath::ScopeId::HOST,
            self.client_addr,
            target,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue,
            reply,
            Arc::clone(&self.alive),
            Arc::clone(&self.stats),
            self.stats
                .outbound_tracker("udp-io-bench", crate::stats::OutboundKind::Node),
        );
        driver.wait_ready().await?;
        if !lease.commit_ready(endpoint) {
            return Err(io::Error::other("commit_ready lost the mapping"));
        }
        driver.start_with_followers(
            lease
                .take_first()
                .ok_or_else(|| io::Error::other("lease has no first datagram"))?,
            Vec::new(),
        )?;
        driver.wait_first_ack().await?;
        drop(lease);
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(SETUP_TIMEOUT, self.client.recv_from(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "first reply timed out"))??;
        if from != target || buf[..n] != *FIRST_PAYLOAD {
            return Err(io::Error::other(
                "first reply did not come from the destination with the echoed payload",
            ));
        }
        Ok(())
    }
}

impl Drop for IoHarness {
    fn drop(&mut self) {
        for target in &self.targets {
            self.pool
                .remove(honk_datapath::ScopeId::HOST, self.client_addr, *target);
        }
    }
}
