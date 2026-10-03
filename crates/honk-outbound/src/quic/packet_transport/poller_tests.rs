//! Receive-yield and writable-readiness behavior of the packet-transport adapter.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Never suspends while packets remain, like a transport decoding frames from
/// an already-buffered stream.
#[derive(Debug)]
struct ImmediatePacketTransport {
    remote: SocketAddr,
    packets: SyncMutex<std::collections::VecDeque<(Vec<u8>, SocketAddr)>>,
    served: AtomicUsize,
}

impl ImmediatePacketTransport {
    fn new(
        remote: SocketAddr,
        packets: impl IntoIterator<Item = (Vec<u8>, SocketAddr)>,
    ) -> Arc<Self> {
        Arc::new(Self {
            remote,
            packets: SyncMutex::new(packets.into_iter().collect()),
            served: AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl PacketTransport for ImmediatePacketTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.remote
    }

    async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let next = self.packets.lock().pop_front();
        let Some((packet, source)) = next else {
            return std::future::pending().await;
        };
        self.served.fetch_add(1, Ordering::SeqCst);
        buf[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), source))
    }
}

#[tokio::test]
async fn ready_burst_beyond_the_queue_reaches_a_live_consumer() {
    const BURST: usize = 2 * TRANSPORT_QUEUE_CAP;
    let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let packets = (0..BURST).map(|i| ((i as u16).to_be_bytes().to_vec(), remote));
    let socket = TransportQuinnSocket::new(ImmediatePacketTransport::new(remote, packets), remote);

    tokio::time::timeout(Duration::from_secs(1), async {
        let mut data = [[0u8; 8]; 16];
        let mut meta = [quinn::udp::RecvMeta::default(); 16];
        let mut next = 0;
        while next < BURST {
            let count = std::future::poll_fn(|cx| {
                let mut bufs = data.each_mut().map(|buf| std::io::IoSliceMut::new(buf));
                quinn::AsyncUdpSocket::poll_recv(&*socket, cx, &mut bufs, &mut meta)
            })
            .await
            .unwrap();
            for (buf, meta) in data.iter().zip(&meta).take(count) {
                assert_eq!(&buf[..meta.len], &(next as u16).to_be_bytes());
                next += 1;
            }
        }
    })
    .await
    .expect("a ready burst overflowed the adapter queue and lost packets");
}

async fn assert_flood_yields(packet: impl Fn() -> (Vec<u8>, SocketAddr)) {
    const FLOOD: usize = 4096;
    let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let transport = ImmediatePacketTransport::new(remote, (0..FLOOD).map(|_| packet()));
    let socket = TransportQuinnSocket::new(transport.clone(), remote);

    // The current-thread runtime schedules this witness behind the workers.
    let served = tokio::spawn({
        let transport = transport.clone();
        async move { transport.served.load(Ordering::SeqCst) }
    })
    .await
    .unwrap();
    assert!(
        served < FLOOD,
        "the receiver served the whole flood in one poll"
    );
    assert!(socket.close_tasks().await);
}

#[tokio::test]
async fn empty_packet_flood_does_not_monopolize_the_runtime() {
    assert_flood_yields(|| (Vec::new(), "127.0.0.1:443".parse().unwrap())).await;
}

#[tokio::test]
async fn wrong_peer_flood_does_not_monopolize_the_runtime() {
    assert_flood_yields(|| (vec![1], "127.0.0.2:443".parse().unwrap())).await;
}

/// Holds every send until the test releases it, so the adapter queue can be filled.
#[derive(Debug)]
struct GatedSendTransport {
    gate: tokio::sync::Semaphore,
}

#[async_trait::async_trait]
impl PacketTransport for GatedSendTransport {
    fn relay_addr(&self) -> SocketAddr {
        "127.0.0.1:443".parse().unwrap()
    }

    async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
        self.gate.acquire().await.unwrap().forget();
        Ok(())
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
}

type BoxedPoller = Pin<Box<dyn quinn::UdpPoller>>;

fn gated_socket() -> (
    Arc<GatedSendTransport>,
    Arc<TransportQuinnSocket>,
    BoxedPoller,
) {
    let transport = Arc::new(GatedSendTransport {
        gate: tokio::sync::Semaphore::new(0),
    });
    let socket = TransportQuinnSocket::new(transport.clone(), transport.relay_addr());
    let poller = quinn::AsyncUdpSocket::create_io_poller(socket.clone());
    (transport, socket, poller)
}

fn send_one(socket: &TransportQuinnSocket) -> io::Result<()> {
    quinn::AsyncUdpSocket::try_send(
        socket,
        &quinn::udp::Transmit {
            destination: socket.remote,
            ecn: None,
            contents: b"x",
            segment_size: None,
            src_ip: None,
        },
    )
}

async fn poll_writable_once(poller: &mut BoxedPoller) -> Poll<io::Result<()>> {
    std::future::poll_fn(|cx| Poll::Ready(quinn::UdpPoller::poll_writable(poller.as_mut(), cx)))
        .await
}

#[tokio::test]
async fn writable_waits_for_queue_space_then_wakes() {
    let (transport, socket, mut poller) = gated_socket();
    for _ in 0..TRANSPORT_QUEUE_CAP {
        send_one(&socket).unwrap();
    }
    // The sender takes the first packet and blocks on the gate; refill the
    // slot it freed so the queue is genuinely full.
    tokio::task::yield_now().await;
    send_one(&socket).unwrap();
    assert_eq!(
        send_one(&socket).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(poll_writable_once(&mut poller).await.is_pending());

    // Only the poller's own wakeup can finish this task: a timer wake on the
    // test task would re-poll an in-line future and find the freed slot.
    let waiter = tokio::spawn(async move {
        std::future::poll_fn(|cx| quinn::UdpPoller::poll_writable(poller.as_mut(), cx)).await
    });
    tokio::task::yield_now().await;
    transport.gate.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("freed queue space never woke the poller")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn dropping_a_waiting_poller_releases_its_reserved_slot() {
    let (_transport, socket, mut poller) = gated_socket();
    for _ in 0..TRANSPORT_QUEUE_CAP {
        send_one(&socket).unwrap();
    }
    assert!(poll_writable_once(&mut poller).await.is_pending());

    // The sender takes the first packet, handing its slot to the waiting poller.
    tokio::task::yield_now().await;
    assert_eq!(
        send_one(&socket).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(poller);
    send_one(&socket).unwrap();
}

#[tokio::test]
async fn writable_readiness_charges_the_cooperative_budget() {
    let (_transport, _socket, mut poller) = gated_socket();
    let (mut ready, mut yields) = (0, 0);
    std::future::poll_fn(|cx| {
        loop {
            match quinn::UdpPoller::poll_writable(poller.as_mut(), cx) {
                Poll::Ready(result) => {
                    result.unwrap();
                    ready += 1;
                    if ready == 1000 {
                        break Poll::Ready(());
                    }
                }
                Poll::Pending => {
                    yields += 1;
                    break Poll::Pending;
                }
            }
        }
    })
    .await;
    assert!(yields > 0, "ready polls never yielded to the scheduler");
}

#[tokio::test]
async fn stored_send_error_beats_an_exhausted_budget() {
    let (_transport, socket, mut poller) = gated_socket();
    let outcome = std::future::poll_fn(|cx| {
        let exhausted =
            (0..10_000).any(|_| quinn::UdpPoller::poll_writable(poller.as_mut(), cx).is_pending());
        assert!(exhausted, "the cooperative budget never ran out");
        *socket.send_error.lock() = Some(TransportIoError::fatal(io::Error::from(
            io::ErrorKind::ConnectionReset,
        )));
        Poll::Ready(quinn::UdpPoller::poll_writable(poller.as_mut(), cx))
    })
    .await;
    let Poll::Ready(Err(error)) = outcome else {
        panic!("an exhausted budget masked the stored send error: {outcome:?}");
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
}

#[tokio::test]
async fn writable_reports_a_closed_queue_as_broken_pipe() {
    let (_transport, socket, mut poller) = gated_socket();
    assert!(socket.close_tasks().await);
    let outcome = poll_writable_once(&mut poller).await;
    let Poll::Ready(Err(error)) = outcome else {
        panic!("closed queue reported as writable: {outcome:?}");
    };
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}
