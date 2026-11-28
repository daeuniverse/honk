use super::*;
use crate::control::{
    netstack::{CAPTURE_MEMORY, capture_tun_realm},
    packet_endpoint::PacketEndpointOwner,
};
use crate::tun::{STANDALONE_TX_CAPS, VNET_BYTES, service_turn};
use honk_netstack::Csum;
use std::{
    future::poll_fn, net::SocketAddr, os::unix::net::UnixDatagram, task::Waker, time::Duration,
};
use tokio::net::{TcpListener, UdpSocket};

struct Fixture {
    queues: Vec<QueueIo>,
    devices: Vec<AsyncFd<UnixDatagram>>,
    peers: Vec<UnixDatagram>,
    drivers: Vec<PacketDriver>,
    realm: PacketRealm,
    endpoints: PacketEndpoints,
    owner: PacketEndpointOwner,
    admission: Arc<AtomicBool>,
    budget: Arc<MemoryBudget>,
    _health: TcpListener,
}

impl Fixture {
    async fn new() -> Self {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let queues = QueueIo::prepare(3, &budget).unwrap();
        let (realm, owners) = capture_tun_realm(1280, 3, STANDALONE_TX_CAPS, &budget).unwrap();
        let admission = Arc::new(AtomicBool::new(false));
        realm
            .install_admission_fence(Arc::clone(&admission))
            .unwrap();
        let mut config = honk_config::Config::default();
        config.ensure_builtin_nodes();
        config.global.dial_mode = "ip".into();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = Some(vec!["127.0.0.1:9".into()]);
        config.global.preconnect_node_count = 0;
        config.global.udp_warm_node_count = 0;
        let plane = crate::control::tests::support::control_plane(config);
        let health = TcpListener::bind("127.0.0.1:0").await.unwrap();
        plane
            .alive_set()
            .set_direct_check_addr(health.local_addr().unwrap().to_string());
        let (endpoints, mut owner, mut drivers) = PacketEndpoints::start_driven(
            plane,
            vec![(realm.clone(), owners)],
            4,
            None,
            realm.scope(),
        )
        .await
        .unwrap();
        poll_fn(|cx| {
            service_turn(&mut drivers, cx, Instant::now(), |_, _| Ok(false)).unwrap();
            owner.poll_ready(cx)
        })
        .await
        .unwrap();
        let (devices, peers) = (0..3)
            .map(|_| {
                let (device, peer) = UnixDatagram::pair().unwrap();
                device.set_nonblocking(true).unwrap();
                peer.set_nonblocking(true).unwrap();
                // SAFETY: the owned socket keeps its descriptor until deregistration.
                (unsafe { AsyncFd::register(device) }.unwrap(), peer)
            })
            .unzip();
        admission.store(true, Ordering::Release);
        Self {
            queues,
            devices,
            peers,
            drivers,
            realm,
            endpoints,
            owner,
            admission,
            budget,
            _health: health,
        }
    }

    fn client(&self, owner: usize) -> SocketAddr {
        self.client_on("192.0.2.10".parse().unwrap(), owner)
    }

    fn client_on(&self, address: std::net::IpAddr, owner: usize) -> SocketAddr {
        (41000..=u16::MAX)
            .map(|port| SocketAddr::new(address, port))
            .find(|&client| self.realm.worker_for_udp(client) == owner)
            .unwrap()
    }

    fn inbox(&self, index: usize) -> parking_lot::MutexGuard<'_, VecDeque<Record>> {
        self.queues[index].handoffs.inboxes[index].records.lock()
    }

    fn turn(&mut self, index: usize, cx: &mut Context<'_>, ingress_at: Instant) -> bool {
        let driver = &mut self.drivers[index];
        driver.begin_turn(Instant::now());
        let more = self.queues[index]
            .poll(
                cx,
                &self.devices[index],
                driver,
                &self.endpoints,
                &self.realm,
                &self.admission,
                ingress_at,
            )
            .unwrap();
        driver.finish_turn(cx, Instant::now());
        more
    }

    fn drain(&mut self, index: usize) {
        self.turn(
            index,
            &mut Context::from_waker(Waker::noop()),
            Instant::now(),
        );
    }

    async fn input(&mut self, index: usize, packet: &[u8], ingress_at: Instant) {
        // DATA_VALID lets tests distinguish real raw passthrough from VERIFY on completion.
        let mut record = vec![0; VNET_BYTES];
        record[0] = 2;
        record.extend_from_slice(packet);
        assert_eq!(self.peers[index].send(&record).unwrap(), record.len());
        drop(self.devices[index].readable().await.unwrap());
        self.turn(index, &mut Context::from_waker(Waker::noop()), ingress_at);
    }

    async fn reply(&mut self, index: usize, buf: &mut [u8]) -> usize {
        poll_fn(|cx| {
            let more = self.turn(index, cx, Instant::now());
            match self.peers[index].recv(buf) {
                Ok(len) => Poll::Ready(len),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if more {
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending
                }
                Err(error) => panic!("unexpected reply socket error: {error}"),
            }
        })
        .await
    }

    async fn finish(mut self) {
        self.admission.store(false, Ordering::Release);
        self.endpoints.close();
        let (plane, joined) = poll_fn(|cx| {
            service_turn(&mut self.drivers, cx, Instant::now(), |_, _| Ok(false)).unwrap();
            self.owner.poll_join_plane(cx)
        })
        .await
        .unwrap();
        joined.unwrap();
        drop(plane);
        let budget = Arc::clone(&self.budget);
        drop(self);
        assert_eq!(budget.used(), 0);
    }
}

fn fragments(source: SocketAddr, destination: SocketAddr, body: &[u8]) -> [Vec<u8>; 2] {
    let mut config = honk_netstack::Config::new([19; 32]);
    config.mode = honk_netstack::Mode::Transparent {
        exclude: Default::default(),
    };
    config.mtu = 1280;
    let now = Instant::now();
    let mut sender = honk_netstack::Stack::new(config, now);
    let mut bytes = [0; 1280];
    let len = sender
        .udp_send_from(source, destination, body, &mut bytes)
        .unwrap();
    let first = bytes[..len].to_vec();
    let len = sender.poll_transmit(now, &mut bytes).unwrap();
    let last = bytes[..len].to_vec();
    assert!(sender.poll_transmit(now, &mut bytes).is_none());
    [first, last]
}

#[tokio::test]
async fn cross_queue_fragments_visit_owner_zero_then_deliver_once_on_canonical_fd() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut f = Fixture::new().await;
        for (bind, address) in [("127.0.0.1:0", "192.0.2.10"), ("[::1]:0", "2001:db8::10")] {
            let upstream = UdpSocket::bind(bind).await.unwrap();
            let client = f.client_on(address.parse().unwrap(), 1);
            let body: Vec<_> = (0..1800).map(|i| (i % 251) as u8).collect();
            let [first, last] = fragments(client, upstream.local_addr().unwrap(), &body);
            let now = Instant::now();
            let expired = now - Duration::from_secs(31);
            // An old queued pair must not obtain a new 30s lifetime when queue zero runs.
            f.input(2, &last, expired).await;
            f.input(1, &first, expired).await;
            assert_eq!(
                f.inbox(0).len(),
                2,
                "both foreign FDs hand fragments to owner zero"
            );
            f.drain(0);
            assert!(f.inbox(1).is_empty());

            let latest = now - Duration::from_millis(2);
            let earliest = now - Duration::from_millis(9);
            f.input(2, &last, latest).await;
            f.input(1, &first, earliest).await;
            f.queues[1].rx.fill(0);
            f.queues[2].rx.fill(0);
            {
                let fragments = f.inbox(0);
                assert_eq!(fragments.len(), 2);
                assert_eq!(fragments[0].cell, last);
                assert_eq!(fragments[1].cell, first);
                assert_eq!(
                    (fragments[0].ingress_at, fragments[1].ingress_at),
                    (latest, earliest)
                );
            }
            f.drain(0);
            {
                let records = f.inbox(1);
                assert_eq!(records.len(), 1);
                let record = &records[0];
                let packet = record
                    .complete
                    .as_ref()
                    .expect("move the original reassembly, without copying it into the cell");
                assert!(record.cell.is_empty());
                assert!(packet.charged_to(&f.budget));
                assert_eq!(record.meta, RxMeta::VERIFY);
                assert_eq!(
                    (record.ingress_at, packet.completion_ingress()),
                    (latest, latest)
                );
            }
            f.drain(1);
            let mut bytes = [0; 2048];
            let (len, source) = upstream.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..len], &body);
            upstream.send_to(b"owner reply", source).await.unwrap();
            let len = f.reply(1, &mut bytes).await;
            let (packet, _) = decode_record(&bytes[..len]).unwrap();
            let ip = wire::parse_ip(packet).unwrap();
            assert_eq!(ip.dst, client.ip());
            let udp = &packet[ip.payload];
            let (_, port, range) = wire::udp::parse(udp).unwrap();
            assert_eq!(port, client.port());
            assert_eq!(&udp[range], b"owner reply");
            for q in [0, 2] {
                f.drain(q);
                assert_eq!(
                    f.peers[q].recv(&mut bytes).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(50), upstream.recv_from(&mut bytes))
                    .await
                    .is_err()
            );
        }
        let handoffs = &f.queues[0].handoffs;
        assert_eq!(
            handoffs.inboxes[0].cross[Dispatch::FragmentToOwner0 as usize].load(Ordering::Relaxed),
            8
        );
        assert_eq!(
            handoffs.inboxes[1].cross[Dispatch::ReassembledToOwner as usize]
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            handoffs.inboxes[1].local[Dispatch::Udp as usize].load(Ordering::Relaxed),
            0
        );
        f.finish().await;
    })
    .await
    .expect("two-stage fragment handoff, one UDP delivery, and owner FD reply");
}

#[tokio::test]
async fn same_queue_raw_is_inline_and_remote_raw_keeps_metadata_and_storage() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut f = Fixture::new().await;
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut bytes = [0; 128];
        let mut received = [0; 128];
        #[derive(Default)]
        struct WakeCount(std::sync::atomic::AtomicUsize);
        impl std::task::Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        for (fd, body) in [
            (2, b"foreign".as_slice()),
            (2, b"rearmed".as_slice()),
            (1, b"inline".as_slice()),
        ] {
            let before = wakes.0.load(Ordering::Relaxed);
            if fd != 1 {
                let turn = ReceiveTurn {
                    index: 1,
                    handoffs: &f.queues[1].handoffs,
                    realm: &f.realm,
                    endpoints: &f.endpoints,
                    admission: &f.admission,
                };
                assert!(!turn.drain(&mut Context::from_waker(&waker)).unwrap());
            }
            let len = wire::udp::emit_packet(
                &mut bytes,
                f.client(1),
                upstream.local_addr().unwrap(),
                body,
            )
            .unwrap();
            // Deliberately invalidate a nonzero UDP checksum. DATA_VALID is authoritative for this raw local-device record.
            let bad = (u16::from_be_bytes([bytes[26], bytes[27]]) ^ 0x8000).max(1);
            bytes[26..28].copy_from_slice(&bad.to_be_bytes());
            let at = Instant::now();
            f.input(fd, &bytes[..len], at).await;
            if fd != 1 {
                assert_eq!(wakes.0.load(Ordering::Relaxed), before + 1);
                f.queues[fd].rx.fill(0xff);
                {
                    let records = f.inbox(1);
                    assert_eq!(records.len(), 1);
                    assert_eq!(records[0].cell, bytes[..len]);
                    assert!(records[0].complete.is_none());
                    assert_eq!(records[0].ingress_at, at);
                    assert_eq!(
                        records[0].meta,
                        RxMeta {
                            csum: Csum::Valid,
                            gso: None
                        }
                    );
                }
                assert_eq!(
                    upstream.try_recv_from(&mut received).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                f.drain(1);
            }
            assert!((0..3).all(|i| f.inbox(i).is_empty()));
            let (n, _) = upstream.recv_from(&mut received).await.unwrap();
            assert_eq!(&received[..n], body);
        }
        assert_eq!(
            f.queues[0].handoffs.inboxes[1].local[Dispatch::Udp as usize].load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            f.queues[0].handoffs.inboxes[1].cross[Dispatch::Udp as usize].load(Ordering::Relaxed),
            2
        );
        // Fill the canonical inbox, then drive the foreign FD with a genuine datagram.
        // No FIFO head is evicted and no other Stack may deliver the refused input.
        let now = Instant::now();
        for i in 0..PER_QUEUE {
            f.queues[0]
                .handoffs
                .send(1, Dispatch::Other, &[i as u8], None, RxMeta::VERIFY, now);
        }
        let len = wire::udp::emit_packet(
            &mut bytes,
            f.client(1),
            upstream.local_addr().unwrap(),
            b"at-capacity",
        )
        .unwrap();
        f.input(2, &bytes[..len], now).await;
        assert_eq!(
            f.queues[0].handoffs.inboxes[1]
                .capacity_drops
                .load(Ordering::Relaxed),
            1
        );
        let [first, last] = fragments(f.client(1), upstream.local_addr().unwrap(), &[0x73; 1800]);
        f.input(2, &last, now).await;
        f.input(0, &first, now).await;
        assert_eq!(
            f.queues[0].handoffs.inboxes[1]
                .capacity_drops
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            f.queues[0].handoffs.inboxes[1]
                .inbox_full
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            f.queues[0].handoffs.inboxes[1]
                .pool_empty
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            f.queues[0].handoffs.inboxes[0].local[Dispatch::FragmentToOwner0 as usize]
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(f.inbox(1).len(), PER_QUEUE);
        assert!(
            f.inbox(1)
                .iter()
                .enumerate()
                .all(|(i, r)| r.cell == [i as u8] && r.ingress_at == now)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), upstream.recv_from(&mut received))
                .await
                .is_err()
        );
        // Closed admission leaves the FD untouched, including when last readiness was cached.
        f.admission.store(false, Ordering::Release);
        f.input(2, &bytes[..len], now).await;
        assert_eq!(
            f.devices[2].get_ref().recv(&mut received).unwrap(),
            len + VNET_BYTES
        );
        f.finish().await;
    })
    .await
    .expect("raw locality, capacity refusal and closed admission");
}

#[test]
fn queue_capacity_is_prepaid_shared_and_refunded_after_last_owner() {
    let budget = MemoryBudget::new(16 << 20);
    let workers = QueueIo::prepare(8, &budget).unwrap();
    let cost = budget.used();
    assert!(cost > 8 * RX_BYTES + CELLS * MAX_IP_BYTES);
    let too_small = MemoryBudget::new(cost - 1);
    assert!(QueueIo::prepare(8, &too_small).is_err());
    assert_eq!(too_small.used(), 0);
    let ceiling = budget.reserve(budget.limit() - cost).unwrap();
    let shared = Arc::clone(&workers[0].handoffs);
    let mut raw = vec![0; MAX_IP_BYTES];
    let now = Instant::now();
    for target in 0..2 {
        for i in 0..PER_QUEUE {
            raw.fill(i as u8);
            shared.send(target, Dispatch::Other, &raw, None, RxMeta::VERIFY, now);
        }
    }
    shared.send(2, Dispatch::Other, &raw, None, RxMeta::VERIFY, now);
    assert_eq!(shared.inboxes[2].capacity_drops.load(Ordering::Relaxed), 1);
    assert_eq!(shared.inboxes[2].pool_empty.load(Ordering::Relaxed), 1);
    assert_eq!(shared.inboxes[2].inbox_full.load(Ordering::Relaxed), 0);
    assert_eq!(
        shared.inboxes[0].max_inbox_depth.load(Ordering::Relaxed),
        PER_QUEUE
    );
    assert_eq!(shared.inboxes[2].max_inbox_depth.load(Ordering::Relaxed), 0);
    assert_eq!(shared.max_pool_in_use.load(Ordering::Relaxed), CELLS);
    assert!(shared.inboxes[2].records.lock().is_empty());
    assert!(shared.free.lock().is_empty());
    for target in 0..2 {
        let mut records = shared.inboxes[target].records.lock();
        assert_eq!(records.len(), PER_QUEUE);
        for i in 0..PER_QUEUE {
            let record = records.pop_front().unwrap();
            assert_eq!(record.cell.len(), MAX_IP_BYTES);
            assert!(record.cell.iter().all(|&v| v == i as u8));
            shared.free.lock().push(record.cell);
        }
    }
    shared.send(2, Dispatch::Other, &raw, None, RxMeta::VERIFY, now);
    assert_eq!(shared.inboxes[2].records.lock().len(), 1);
    assert_eq!(
        shared.inboxes[2].cross[Dispatch::Other as usize].load(Ordering::Relaxed),
        1
    );
    assert_eq!(shared.inboxes[2].max_inbox_depth.load(Ordering::Relaxed), 1);
    assert_eq!(shared.max_pool_in_use.load(Ordering::Relaxed), CELLS);
    drop(ceiling);
    drop(workers);
    assert_eq!(budget.used(), cost);
    drop(shared);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn tcp_and_local_reassembly_are_counted_at_the_dispatch_boundary() {
    let mut f = Fixture::new().await;
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = peer.local_addr().unwrap();
    let src = f.client(0);
    let home = f.realm.worker_for_tcp(src, dst);
    let mut bytes = [0; 64];
    let n = wire::tcp::emit_packet(
        &mut bytes,
        src.ip(),
        dst.ip(),
        &wire::tcp::Header {
            src_port: src.port(),
            dst_port: dst.port(),
            seq: 5,
            ack: 1,
            flags: wire::tcp::ACK,
            window: 4096,
            urgent: 0,
            options: Default::default(),
        },
        [&[], &[]],
    )
    .unwrap();
    let now = Instant::now();
    f.input(home, &bytes[..n], now).await;
    f.input((home + 1) % 3, &bytes[..n], now).await;
    f.drain(home);
    for packet in fragments(src, dst, &[0x41; 1800]) {
        f.input(0, &packet, now).await;
    }
    let inboxes = &f.queues[0].handoffs.inboxes;
    assert_eq!(
        inboxes[home].local[Dispatch::Tcp as usize].load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        inboxes[home].cross[Dispatch::Tcp as usize].load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        inboxes[0].local[Dispatch::FragmentToOwner0 as usize].load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        inboxes[0].local[Dispatch::ReassembledToOwner as usize].load(Ordering::Relaxed),
        1
    );
    f.finish().await;
}

#[tokio::test]
async fn real_queue_tasks_wake_for_handoff_and_return_their_driving_rights() {
    exercise_queue_tasks(false).await;
}

#[tokio::test]
async fn fatal_middle_queue_fences_all_workers_and_keeps_files_until_join() {
    exercise_queue_tasks(true).await;
}

async fn exercise_queue_tasks(fatal: bool) {
    use crate::tun::multiqueue::{Capture, CloseOnDrop, Phase, Worker, publish_after_ready};
    use tokio::sync::{oneshot, watch};
    tokio::time::timeout(Duration::from_secs(10), async {
        let f = Fixture::new().await;
        let client = f.client(1);
        let Fixture {
            queues,
            devices,
            peers,
            drivers,
            realm,
            endpoints,
            owner,
            admission,
            budget,
            _health,
        } = f;
        admission.store(false, Ordering::Release);
        let gate = Arc::new(Capture {
            phase: watch::channel(Phase::Starting).0,
            open: admission,
        });
        let anchors: Vec<_> = devices.into_iter().map(Arc::new).collect();
        let peers: Vec<_> = peers
            .into_iter()
            .map(|p| tokio::net::UnixDatagram::from_std(p).unwrap())
            .collect();
        let mut tasks = tokio::task::JoinSet::new();
        let mut ready = Vec::new();
        for ((fd, driver), queue) in anchors.iter().zip(drivers).zip(queues) {
            let (send, ack) = oneshot::channel();
            let worker = Worker {
                driver,
                queue,
                realm: realm.clone(),
                endpoints: endpoints.clone(),
                fence: CloseOnDrop(gate.clone()),
            };
            tasks.spawn(worker.run(fd.clone(), send));
            ready.push(ack);
        }
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut record = [0; 256];
        let n = wire::udp::emit_packet(
            &mut record[VNET_BYTES..],
            client,
            upstream.local_addr().unwrap(),
            b"before ready",
        )
        .unwrap();
        peers[2].send(&record[..VNET_BYTES + n]).await.unwrap();
        publish_after_ready(ready, async { Ok(()) }, || {
            assert_eq!(
                upstream.try_recv_from(&mut record).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            gate.publish(|| Ok(()), || endpoints.capture_ready())
        })
        .await
        .unwrap();
        let (n, source) = upstream.recv_from(&mut record).await.unwrap();
        assert_eq!(&record[..n], b"before ready");
        upstream.send_to(b"from owner one", source).await.unwrap();
        let n = peers[1].recv(&mut record).await.unwrap();
        let (packet, _) = decode_record(&record[..n]).unwrap();
        let ip = wire::parse_ip(packet).unwrap();
        let udp = &packet[ip.payload];
        let (_, port, payload) = wire::udp::parse(udp).unwrap();
        assert_eq!((ip.dst, port), (client.ip(), client.port()));
        assert_eq!(&udp[payload], b"from owner one");
        if fatal {
            peers[1].send(&[]).await.unwrap();
            gate.closed().await;
            assert!(!gate.open.load(Ordering::Acquire));
        } else {
            gate.close();
        }
        endpoints.close();
        let (plane, result) = owner.join_plane().await.unwrap();
        assert_eq!(
            result.is_err(),
            fatal,
            "unexpected supervisor outcome: {result:?}"
        );
        gate.phase.send_replace(Phase::Joined);
        let mut failures = 0;
        while let Some(task) = tasks.join_next().await {
            if let Err(error) = task.unwrap() {
                assert!(
                    error.to_string().contains("reader reached EOF"),
                    "{error:#}"
                );
                failures += 1;
            }
        }
        assert_eq!(failures, usize::from(fatal));
        peers[1].send(b"anchor").await.unwrap();
        let n = anchors[1].get_ref().recv(&mut record).unwrap();
        assert_eq!(&record[..n], b"anchor");
        drop((anchors, realm, endpoints, plane));
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("TUN queue startup, handoff, selected reply and joined scope retirement");
}
