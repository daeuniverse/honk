use super::*;
use crate::control::netstack::{
    DirectRelayFence, DirectRelayOwner, FlowIo, OutputLease, PacketOwner, PacketScope,
    RuntimeLimits,
};
use crate::control::tests::support::{canonical_socks5, dns_query_payload};
use anyhow::Context as _;
use honk_netstack::{ExcludeSet, FlowId, MemoryBudget, Mode, Stack, StreamError, TcpState};
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

struct Wire {
    scope: PacketScope,
    owner: Option<PacketOwner>,
    client: Stack,
    id: FlowId,
    now: std::time::Instant,
    received: Vec<u8>,
    eof: bool,
    hold_data: bool,
    held: Option<OutputLease>,
    budget: Arc<MemoryBudget>,
    qualified_rx: usize,
}

impl Wire {
    fn connect(destination: SocketAddr) -> anyhow::Result<(Self, FlowIo)> {
        Self::connect_with_send_limit(destination, 64 << 10)
    }

    fn connect_with_send_limit(
        destination: SocketAddr,
        send_limit: usize,
    ) -> anyhow::Result<(Self, FlowIo)> {
        let now = std::time::Instant::now();
        let budget = MemoryBudget::new(64 << 20);
        let mut cfg = honk_netstack::Config::new([31; 32]);
        cfg.max_flows = 8;
        cfg.memory_limit = 2 << 20;
        cfg.half_open_max = 8;
        cfg.tcp_rcv_buf_max = 64 << 10;
        cfg.tcp_snd_buf_max = send_limit;
        cfg.mode = Mode::Transparent {
            exclude: ExcludeSet::default(),
        };
        let (scope, owner) = PacketScope::new(
            cfg,
            Arc::clone(&budget),
            RuntimeLimits {
                max_slots: 8,
                control_frames: 2,
                bulk_frames: 2,
                max_waiters: 8,
            },
            now,
        )?;
        let mut cfg = honk_netstack::Config::new([47; 32]);
        cfg.local_v4 = Some("10.0.0.2".parse()?);
        cfg.local_v6 = Some("fd00::2".parse()?);
        cfg.max_flows = 8;
        cfg.tcp_rcv_buf_max = 64 << 10;
        cfg.tcp_snd_buf_max = 64 << 10;
        cfg.shared_budget = Some(Arc::clone(&budget));
        let mut client = Stack::new(cfg, now);
        let id = client
            .tcp_connect(now, destination)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let mut wire = Self {
            scope,
            owner: Some(owner),
            client,
            id,
            now,
            received: Vec::new(),
            eof: false,
            hold_data: false,
            held: None,
            budget,
            qualified_rx: 0,
        };
        wire.pump();
        let (syn, flow) = wire.scope.poll_accept().expect("real peer SYN admitted");
        assert_eq!(syn.original_dst, destination);
        assert_eq!(flow.local_addr(), destination);
        assert_eq!(flow.peer_addr(), syn.client);
        assert_ne!(flow.scope(), honk_datapath::ScopeId::HOST);
        wire.pump();
        assert_eq!(wire.client.tcp_state(id), Some(TcpState::Established));
        assert_eq!(
            wire.qualified_rx, 0,
            "handshake alone has no winning outbound"
        );
        Ok((wire, flow))
    }

    fn pump(&mut self) {
        self.now = self.now.max(std::time::Instant::now());
        let mut packet = [0; 2048];
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        for _ in 0..8 {
            self.client.handle_timeout(self.now);
            for _ in 0..64 {
                let Some(length) = self.client.poll_transmit(self.now, &mut packet) else {
                    break;
                };
                let (_, received) =
                    self.scope
                        .receive_with_source(&packet[..length], self.now, false, |_, _| true);
                self.qualified_rx += usize::from(received.qualified_rx);
            }
            self.scope.drive(self.now);
            for _ in 0..64 {
                let Poll::Ready(Some(output)) = self.scope.poll_output(&mut cx) else {
                    break;
                };
                assert_eq!(output.scope(), self.scope.scope());
                let ip =
                    honk_netstack::wire::parse_ip(output.packet()).expect("complete IP output");
                let segment = &output.packet()[ip.payload];
                let (_, offset) = honk_netstack::wire::tcp::parse(segment).expect("TCP output");
                let data = segment.len() > offset;
                let _ = self.client.receive(self.now, output.packet());
                if self.hold_data && data && self.held.is_none() {
                    assert!(output.flow_id().is_some());
                    self.held = Some(output);
                } else {
                    output.release();
                }
            }
            while self.client.poll_event().is_some() {}
            loop {
                match self.client.tcp_read(self.id, &mut packet) {
                    Ok(0) | Err(StreamError::Closed | StreamError::Reset | StreamError::Stale) => {
                        self.eof = true;
                        break;
                    }
                    Ok(length) => {
                        self.received.extend_from_slice(&packet[..length]);
                        assert!(self.received.len() <= 64 << 10);
                    }
                    Err(StreamError::WouldBlock) => break,
                    Err(error) => panic!("packet client read: {error:?}"),
                }
            }
        }
    }

    async fn until(&mut self, mut done: impl FnMut(&mut Self) -> bool) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                self.pump();
                if done(self) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        Ok(())
    }

    fn send(&mut self, bytes: &[u8]) {
        assert_eq!(self.client.tcp_write(self.id, bytes), Ok(bytes.len()));
        self.pump();
    }

    async fn settle(
        &mut self,
        task: &tokio::task::JoinHandle<anyhow::Result<()>>,
    ) -> anyhow::Result<()> {
        self.until(|wire| {
            wire.now += Duration::from_secs(130);
            task.is_finished()
        })
        .await
    }

    fn relay_owner(
        &self,
        runtime: &tokio::runtime::Handle,
    ) -> anyhow::Result<(DirectRelayOwner, honk_netstack::MemoryReservation)> {
        DirectRelayOwner {
            runtime: runtime.clone(),
            fence: DirectRelayFence::new(&self.budget)?,
        }
        .with_completion_credit(&self.budget)
        .context("packet completion credit")
    }

    async fn finish(mut self) {
        self.held = None;
        self.scope.shutdown(true);
        self.pump();
        self.owner.take().expect("one runtime owner").run().await;
        let budget = Arc::clone(&self.budget);
        drop(self);
        assert_eq!(budget.used(), 0);
    }
}

const RELAY_WAIT: Duration = Duration::from_secs(5);
const MEASURED_SELECTOR: &str = "measured_direct";
const RELAY_MEMORY: usize = crate::relay::COPY_BUFFER_MEMORY + crate::sniffing::SNIFF_MEMORY;

fn select_leaf(config: &mut Config, leaf: uuid::Uuid) {
    use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};

    config.groups.push(Group {
        name: MEASURED_SELECTOR.into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![leaf],
        ..Default::default()
    });
    config.routing.rules.push(RoutingRule {
        name: "packet-tcp".into(),
        condition: RoutingCondition {
            protocol: vec!["tcp".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple(MEASURED_SELECTOR.into()),
        priority: 0,
        must: false,
        mark: None,
    });
    config.routing.default_outbound = "block".into();
}

fn relay_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

fn wait_synchronously(reason: &str, mut ready: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + RELAY_WAIT;
    while !ready() {
        assert!(std::time::Instant::now() < deadline, "{reason}");
        std::thread::yield_now();
    }
}

#[test]
fn owned_packet_cancel_during_sniff_needs_no_owner_or_packet_driver() -> anyhow::Result<()> {
    let owner = relay_runtime()?;
    let shared = relay_runtime()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    shared.block_on(async {
        let (wire, flow) = Wire::connect(listener.local_addr()?)?;
        let funding = flow.reserve_memory(RELAY_MEMORY)?;
        let target = wire.relay_owner(owner.handle())?;
        let fence = Arc::clone(&target.0.fence);
        let mut config = config();
        config.global.dial_mode = "domain+".into();
        select_leaf(&mut config, honk_config::config::DIRECT_NODE_ID);
        let plane = plane(config)?;
        let handle = plane.spawn_handle();
        handle.connection_tracker.enable();
        let (abort, registration) = futures::future::AbortHandle::new_pair();
        {
            let serving = handle.serve_owned_packet_connection(flow, target, registration);
            tokio::pin!(serving);
            assert!(futures::poll!(&mut serving).is_pending());
            abort.abort();
            tokio::time::timeout(RELAY_WAIT, serving).await??;
        }
        assert!(futures::poll!(std::pin::pin!(fence.close_and_join())).is_ready());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(handle.connection_tracker.snapshot().is_empty());
        let stats = handle
            .stats
            .outbound_tracker(MEASURED_SELECTOR, crate::stats::OutboundKind::Group)
            .snapshot();
        assert_eq!(
            (stats.total_conns, stats.tx_bytes, stats.rx_bytes),
            (0, 0, 0)
        );
        assert_eq!(wire.qualified_rx, 0);
        drop(fence);
        drop(funding);
        tokio::time::timeout(RELAY_WAIT, wire.finish()).await?;
        Ok(())
    })
}

#[test]
fn owned_packet_direct_relays_with_shared_thread_frozen_and_joins_on_abort() -> anyhow::Result<()> {
    owned_packet_direct_relay(DirectRelayCase::RegistryAbort)
}

#[test]
fn owned_packet_direct_writes_sniffed_http_prefix_on_owner_once() -> anyhow::Result<()> {
    owned_packet_direct_relay(DirectRelayCase::SniffedPrefix)
}

#[test]
fn owned_packet_direct_tracker_close_stops_owner_before_packet_retirement() -> anyhow::Result<()> {
    owned_packet_direct_relay(DirectRelayCase::TrackerClose)
}

enum DirectRelayCase {
    RegistryAbort,
    SniffedPrefix,
    TrackerClose,
}

async fn accept_tracked_direct(
    listener: &TcpListener,
    handle: &ControlPlaneHandle,
    serving: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<std::net::TcpStream> {
    let ready = async {
        let (peer, _) = listener.accept().await?;
        while handle.connection_tracker.snapshot().is_empty() {
            tokio::task::yield_now().await;
        }
        peer.into_std()
    };
    let peer = tokio::select! {
        biased;
        result = serving => anyhow::bail!("relay ended before transfer: {result:?}"),
        peer = tokio::time::timeout(RELAY_WAIT, ready) => peer??,
    };
    let tracked = handle.connection_tracker.snapshot();
    assert_eq!(tracked.len(), 1);
    assert_eq!(
        tracked[0].chains,
        [Config::BUILTIN_DIRECT_NODE, MEASURED_SELECTOR]
    );
    Ok(peer)
}

fn owned_packet_direct_relay(case: DirectRelayCase) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    use std::sync::mpsc;

    const WINDOW: usize = 4096;
    let (dial_mode, prefix): (&str, &[u8]) = match case {
        DirectRelayCase::SniffedPrefix => (
            "domain+",
            b"GET /prefix HTTP/1.1\r\nHost: prefix.example\r\n\r\n",
        ),
        _ => ("ip", b""),
    };
    let tracker_close = matches!(case, DirectRelayCase::TrackerClose);
    let shared = relay_runtime()?;
    let owner = relay_runtime()?;
    let owner_handle = owner.handle().clone();
    assert_ne!(owner_handle.id(), shared.handle().id());
    std::thread::scope(|threads| {
        // The sender drops before the scoped join, including during assertion unwinds.
        let (_stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let owner_runtime = &owner;
        shared.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let (mut wire, flow) = Wire::connect_with_send_limit(listener.local_addr()?, WINDOW)?;
            let flow_id = flow.flow_id();
            let funding = flow.reserve_memory(RELAY_MEMORY)?;
            let mut config = config();
            config.global.dial_mode = dial_mode.into();
            select_leaf(&mut config, honk_config::config::DIRECT_NODE_ID);
            let plane = plane(config)?;
            let handle = plane.spawn_handle();
            handle.connection_tracker.enable();
            let (abort, registration) = futures::future::AbortHandle::new_pair();
            let mut serving = Box::pin(handle.serve_owned_packet_connection(
                flow,
                wire.relay_owner(&owner_handle)?,
                registration,
            ));
            if !prefix.is_empty() {
                wire.send(prefix);
            }
            let mut peer = accept_tracked_direct(&listener, &handle, serving.as_mut()).await?;
            if !prefix.is_empty() {
                let tracked = handle.connection_tracker.snapshot();
                assert_eq!(tracked[0].domain.as_deref(), Some("prefix.example"));
                assert_eq!(tracked[0].upload, 0);
                assert_eq!(
                    peer.read(&mut [0]).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock,
                    "shared wrote the sniff prefix before the owner was polled"
                );
            }
            peer.set_nonblocking(false)?;
            peer.set_read_timeout(Some(RELAY_WAIT))?;
            peer.set_write_timeout(Some(RELAY_WAIT))?;

            wire.send(b"a");
            // Dial and winner publication completed on shared while the owner was unpolled.
            threads.spawn(move || {
                let _ = owner_runtime.block_on(stopped);
            });
            if !prefix.is_empty() {
                let mut received = vec![0; prefix.len()];
                peer.read_exact(&mut received)?;
                assert_eq!(received, prefix);
            }
            // Shared stays frozen until the peer and packet client have received their bytes.
            let mut singleton = [0];
            peer.read_exact(&mut singleton)
                .context("first Direct byte did not reach upstream while shared was frozen")?;
            assert_eq!(&singleton, b"a");

            let response: Vec<_> = (0..2 * WINDOW + 1).map(|i| (i % 251) as u8).collect();
            let outbound = handle
                .stats
                .outbound_tracker(MEASURED_SELECTOR, crate::stats::OutboundKind::Group);
            peer.write_all(&response)?;
            // The tracker counts socket reads. Once it exceeds the window, the next owner
            // turn proves the relay has actually parked on an unacknowledged packet write.
            wait_synchronously("relay did not read beyond the packet send buffer", || {
                outbound.snapshot().rx_bytes > WINDOW as u64
            });
            let (turn, ran) = mpsc::channel();
            owner_handle.spawn(async move {
                let _ = turn.send(());
            });
            ran.recv_timeout(RELAY_WAIT)?;
            assert!(wire.received.is_empty());
            wire.hold_data = true;
            let half_close = !prefix.is_empty();
            if half_close {
                peer.shutdown(std::net::Shutdown::Write)?;
            }
            // Queue the reverse byte while the download is window-blocked. The half-closed
            // peer must still receive it even when the test thread is descheduled.
            wire.send(b"b");
            peer.read_exact(&mut singleton)?;
            assert_eq!(&singleton, b"b");
            wait_synchronously("ACKs did not resume the download", || {
                wire.pump();
                wire.received.len() == response.len() && (!half_close || wire.eof)
            });
            assert_eq!(wire.received, response);
            assert_eq!(wire.held.as_ref().unwrap().flow_id(), Some(flow_id));
            assert_eq!(wire.eof, half_close);
            let state = if half_close {
                TcpState::CloseWait
            } else {
                TcpState::Established
            };
            assert_eq!(wire.client.tcp_state(wire.id), Some(state));
            assert!(wire.qualified_rx > 0);

            let id = handle
                .connection_tracker
                .snapshot()
                .pop()
                .expect("live Direct connection")
                .id;
            let closing = handle.connection_tracker.close_id(&id);
            tokio::pin!(closing);
            if tracker_close {
                peer.set_nonblocking(true)?;
                assert_eq!(
                    peer.peek(&mut singleton)
                        .expect_err("upstream must still be open before tracker close")
                        .kind(),
                    std::io::ErrorKind::WouldBlock
                );
                peer.set_nonblocking(false)?;
                assert!(futures::poll!(&mut closing).is_pending());
                // The owner must stop the socket while the shared connection task is unpolled.
                assert_eq!(
                    peer.read(&mut singleton)
                        .context("tracker close did not stop the owner socket")?,
                    0,
                    "expected upstream EOF before resuming shared"
                );

                tokio::time::timeout(RELAY_WAIT, async {
                    loop {
                        assert!(futures::poll!(&mut serving).is_pending());
                        wire.pump();
                        if wire.eof {
                            assert_eq!(wire.client.tcp_state(wire.id), Some(TcpState::CloseWait));
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .context("joined relay did not send a packet FIN")?;

                wire.client.tcp_shutdown(wire.id)?;
                wait_synchronously("packet FIN/ACK did not reach TIME_WAIT", || {
                    wire.pump();
                    wire.client.tcp_state(wire.id) == Some(TcpState::Closed)
                        && wire.scope.stats().unwrap().timewait_entries == 1
                });
                // Expire the protocol owner so only the exported lease can hold close open.
                wire.now += Duration::from_secs(60);
                wire.pump();
                let protocol = wire.scope.stats().unwrap();
                assert_eq!((protocol.flows, protocol.timewait_entries), (0, 0));
                assert!(futures::poll!(&mut serving).is_pending());
            } else if half_close {
                abort.abort();
            } else {
                let (park, parked) = mpsc::channel();
                let (resume, resumed) = mpsc::channel::<()>();
                let blocker = owner_handle.spawn(async move {
                    park.send((
                        tokio::runtime::Handle::current().id(),
                        std::thread::current().id(),
                    ))
                    .unwrap();
                    resumed.recv_timeout(RELAY_WAIT)
                });
                let (runtime, thread) = parked.recv_timeout(RELAY_WAIT)?;
                assert_eq!(runtime, owner_handle.id());
                assert_ne!(thread, std::thread::current().id());
                abort.abort();
                assert!(
                    futures::poll!(&mut serving).is_pending(),
                    "abort must join the parked owner"
                );
                resume.send(())?;
                tokio::time::timeout(RELAY_WAIT, blocker).await???;
            }
            if !tracker_close {
                tokio::time::timeout(RELAY_WAIT, &mut serving).await??;
                assert_eq!(peer.read(&mut singleton)?, 0);
            }
            wire.pump();

            let tracked = handle.connection_tracker.snapshot();
            assert_eq!(tracked.len(), 1);
            assert_eq!(tracked[0].id, id);
            let bytes = response.len() as u64;
            let upload = prefix.len() as u64 + 2;
            assert_eq!((tracked[0].upload, tracked[0].download), (upload, bytes));
            assert!(
                futures::poll!(&mut closing).is_pending(),
                "an exported packet still owns the flow"
            );
            let stats = outbound.snapshot();
            assert_eq!((stats.active_conns, stats.total_conns), (1, 1));
            wire.held.take().unwrap().release();
            wire.pump();
            if tracker_close {
                tokio::time::timeout(RELAY_WAIT, &mut serving).await??;
                assert!(wire.scope.is_protocol_quiescent());
            }
            drop(serving);
            assert_eq!(
                tokio::time::timeout(RELAY_WAIT, closing).await?,
                crate::connection_tracker::CloseOutcome::Closed
            );
            assert!(handle.connection_tracker.snapshot().is_empty());
            let stats = outbound.snapshot();
            assert_eq!((stats.active_conns, stats.total_conns), (0, 1));
            assert_eq!((stats.tx_bytes, stats.rx_bytes), (upload, bytes));
            drop(funding);
            tokio::time::timeout(RELAY_WAIT, wire.finish()).await?;
            Ok(())
        })
    })
}

#[test]
fn owned_packet_direct_completed_reset_survives_logical_abort() -> anyhow::Result<()> {
    use tokio::sync::mpsc::{UnboundedSender, error::TryRecvError, unbounded_channel};

    struct JoinWake(UnboundedSender<()>);
    impl futures::task::ArcWake for JoinWake {
        fn wake_by_ref(wake: &Arc<Self>) {
            let _ = wake.0.send(());
        }
    }

    let shared = relay_runtime()?;
    let owner = relay_runtime()?;
    assert_ne!(owner.handle().id(), shared.handle().id());
    let listener = shared.block_on(TcpListener::bind("127.0.0.1:0"))?;
    let (mut wire, flow) = Wire::connect(listener.local_addr()?)?;
    let funding = flow.reserve_memory(RELAY_MEMORY)?;
    let flow_id = flow.flow_id();
    let mut retirement = flow.retirement();
    let mut config = config();
    select_leaf(&mut config, honk_config::config::DIRECT_NODE_ID);
    let plane = shared.block_on(async { plane(config) })?;
    let handle = plane.spawn_handle();
    handle.connection_tracker.enable();
    let outbound = handle
        .stats
        .outbound_tracker(MEASURED_SELECTOR, crate::stats::OutboundKind::Group);
    let (abort, registration) = futures::future::AbortHandle::new_pair();
    let mut serving = Box::pin(handle.serve_owned_packet_connection(
        flow,
        wire.relay_owner(owner.handle())?,
        registration,
    ));
    let peer = shared.block_on(accept_tracked_direct(&listener, &handle, serving.as_mut()))?;
    // No cancellation or fence close can wake this fresh join waiter before the peer resets.
    let (notify, mut wakes) = unbounded_channel();
    let waker = futures::task::waker(Arc::new(JoinWake(notify)));
    {
        let _entered = shared.enter();
        assert!(
            serving
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
    }
    owner.block_on(async {
        let mut peer = tokio::net::TcpStream::from_std(peer)?;
        wire.send(b"x");
        let mut byte = [0];
        tokio::time::timeout(RELAY_WAIT, peer.read_exact(&mut byte)).await??;
        assert_eq!(&byte, b"x");
        wire.hold_data = true;
        tokio::time::timeout(RELAY_WAIT, peer.write_all(b"y")).await??;
        wire.until(|wire| wire.held.is_some()).await?;
        assert_eq!(wire.received, b"y");
        assert_eq!(wire.held.as_ref().unwrap().flow_id(), Some(flow_id));
        assert!(matches!(wakes.try_recv(), Err(TryRecvError::Empty)));
        socket2::SockRef::from(&peer).set_linger(Some(Duration::ZERO))?;
        drop(peer);
        tokio::time::timeout(RELAY_WAIT, wakes.recv())
            .await?
            .context("owner join waker was dropped")?;
        Ok::<_, anyhow::Error>(())
    })?;
    assert_eq!(outbound.snapshot().errors, 0);
    abort.abort();
    shared.block_on(async {
        tokio::time::timeout(RELAY_WAIT, &mut serving).await??;
        drop(serving);
        assert_eq!(
            outbound.snapshot().errors,
            1,
            "completed owner reset must count once"
        );
        wire.pump();
        assert_eq!(outbound.snapshot().active_conns, 1);
        {
            let wait = retirement.wait();
            tokio::pin!(wait);
            assert!(futures::poll!(&mut wait).is_pending());
            wire.held.take().unwrap().release();
            wire.pump();
            tokio::time::timeout(RELAY_WAIT, wait).await??;
        }
        drop(retirement);
        drop(funding);
        tokio::time::timeout(RELAY_WAIT, wire.finish()).await?;
        assert!(handle.connection_tracker.snapshot().is_empty());
        let stats = outbound.snapshot();
        assert_eq!(
            (stats.total_conns, stats.active_conns, stats.errors),
            (1, 0, 1)
        );
        assert_eq!((stats.tx_bytes, stats.rx_bytes), (1, 1));
        Ok(())
    })
}

#[test]
fn fatal_fence_joins_blocked_direct_owner_before_packet_retirement() -> anyhow::Result<()> {
    use std::io::{ErrorKind, Read};

    const WINDOW: usize = 4096;
    let shared = relay_runtime()?;
    let owner = relay_runtime()?;
    let listener = shared.block_on(TcpListener::bind("127.0.0.1:0"))?;
    let (mut wire, flow) = Wire::connect_with_send_limit(listener.local_addr()?, WINDOW)?;
    let funding = flow.reserve_memory(RELAY_MEMORY)?;
    let target = wire.relay_owner(owner.handle())?;
    let fence = Arc::clone(&target.0.fence);
    let flow_id = flow.flow_id();
    let mut config = config();
    select_leaf(&mut config, honk_config::config::DIRECT_NODE_ID);
    let plane = shared.block_on(async { plane(config) })?;
    let handle = plane.spawn_handle();
    handle.connection_tracker.enable();
    let outbound = handle
        .stats
        .outbound_tracker(MEASURED_SELECTOR, crate::stats::OutboundKind::Group);
    let worker = handle.clone();
    let (_abort, registration) = futures::future::AbortHandle::new_pair();
    let mut serving = shared.spawn(async move {
        worker
            .serve_owned_packet_connection(flow, target, registration)
            .await
    });
    let peer = shared.block_on(accept_tracked_direct(&listener, &handle, async {
        (&mut serving).await?
    }))?;
    let mut peer = owner.block_on(async {
        let mut peer = tokio::net::TcpStream::from_std(peer)?;
        wire.hold_data = true;
        tokio::time::timeout(RELAY_WAIT, peer.write_all(b"y")).await??;
        wire.until(|wire| wire.held.is_some()).await?;
        assert_eq!(wire.held.as_ref().unwrap().flow_id(), Some(flow_id));
        assert_eq!(wire.received, b"y");
        // Stop pumping ACKs. Leave more socket data than the original flow can accept.
        tokio::time::timeout(RELAY_WAIT, peer.write_all(&[7; WINDOW * 2])).await??;
        tokio::time::timeout(RELAY_WAIT, async {
            while outbound.snapshot().rx_bytes <= WINDOW as u64 + 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok::<_, anyhow::Error>(peer.into_std()?)
    })?;

    std::thread::scope(|threads| {
        let (_stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let owner_runtime = &owner;
        shared.block_on(async {
            {
                let drain = fence.close_and_join();
                tokio::pin!(drain);
                assert!(
                    futures::poll!(&mut drain).is_pending(),
                    "fatal close returned before the parked owner joined"
                );
                tokio::task::yield_now().await;
                assert!(
                    futures::poll!(&mut drain).is_pending(),
                    "owner is still parked"
                );
                threads.spawn(move || {
                    let _ = owner_runtime.block_on(stopped);
                });
                tokio::time::timeout(RELAY_WAIT, drain).await?;
            }
            peer.set_nonblocking(false)?;
            peer.set_read_timeout(Some(RELAY_WAIT))?;
            match peer.read(&mut [0]) {
                Ok(0) => {}
                Err(error) if error.kind() == ErrorKind::ConnectionReset => {}
                result => panic!("joined relay still owns its peer socket: {result:?}"),
            }
            wire.pump();
            assert_eq!(wire.held.as_ref().unwrap().flow_id(), Some(flow_id));
            let tracked = handle.connection_tracker.snapshot();
            assert_eq!(tracked.len(), 1);
            assert_eq!(outbound.snapshot().active_conns, 1);
            let closing = handle.connection_tracker.close_id(&tracked[0].id);
            tokio::pin!(closing);
            assert!(futures::poll!(&mut closing).is_pending());
            wire.held.take().unwrap().release();
            wire.pump();
            wire.settle(&serving).await?;
            serving.await??;
            assert_eq!(
                tokio::time::timeout(RELAY_WAIT, closing).await?,
                crate::connection_tracker::CloseOutcome::Closed
            );
            assert!(handle.connection_tracker.snapshot().is_empty());
            assert_eq!(outbound.snapshot().active_conns, 0);
            drop(fence);
            drop(funding);
            tokio::time::timeout(RELAY_WAIT, wire.finish()).await?;
            Ok(())
        })
    })
}

#[test]
fn owned_packet_raw_socks5_winner_relays_while_owner_is_unpolled() -> anyhow::Result<()> {
    let owner = relay_runtime()?;
    let shared = relay_runtime()?;
    assert_ne!(owner.handle().id(), shared.handle().id());
    shared.block_on(async {
        tokio::time::timeout(RELAY_WAIT, async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let (mut wire, flow) = Wire::connect("192.0.2.1:443".parse()?)?;
            let funding = flow.reserve_memory(RELAY_MEMORY)?;
            let mut config = config();
            let node = canonical_socks5(
                "raw-socks",
                "127.0.0.1",
                listener.local_addr()?.port(),
                None,
            );
            select_leaf(&mut config, node.id);
            config.nodes.push(node);
            let plane = plane(config)?;
            let handle = plane.spawn_handle();
            handle.connection_tracker.enable();
            let worker = handle.clone();
            let (abort, registration) = futures::future::AbortHandle::new_pair();
            let target = wire.relay_owner(owner.handle())?;
            let serving = tokio::spawn(async move {
                worker
                    .serve_owned_packet_connection(flow, target, registration)
                    .await
            });
            let (mut peer, _) = listener.accept().await?;
            let mut greeting = [0; 3];
            peer.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 1, 0]);
            peer.write_all(&[5, 0]).await?;
            let mut connect = [0; 10];
            peer.read_exact(&mut connect).await?;
            assert_eq!(connect, [5, 1, 0, 1, 192, 0, 2, 1, 1, 187]);
            peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
            while handle.connection_tracker.snapshot().is_empty() {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                handle.connection_tracker.snapshot()[0].chains,
                ["raw-socks", MEASURED_SELECTOR]
            );
            assert_eq!(
                owner.metrics().num_alive_tasks(),
                0,
                "SOCKS5 CONNECT published work on the unpolled Direct owner"
            );
            // Stock SOCKS5 hands back its concrete TcpStream after CONNECT. Only shared can poll it.
            wire.send(b"s");
            let mut singleton = [0];
            peer.read_exact(&mut singleton).await?;
            assert_eq!(&singleton, b"s");
            peer.write_all(b"r").await?;
            wire.until(|wire| !wire.received.is_empty()).await?;
            assert_eq!(wire.received, b"r");
            abort.abort();
            serving.await??;
            drop(funding);
            wire.finish().await;
            Ok(())
        })
        .await?
    })
}

fn config() -> Config {
    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.nfqueue_enable = false;
    config.global.store_subscribe = false;
    config.global.preconnect_node_count = 0;
    config.routing.default_outbound = "direct".into();
    config
}

fn plane(config: Config) -> anyhow::Result<ControlPlane> {
    let resolver = DnsResolver::new(&config.dns)?;
    let forwarder = resolver.forwarder();
    let router = Router::from_config(&config.routing)?;
    ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(ProxyRegistry::default_resolver()?),
        resolver,
        forwarder,
    )
}

#[tokio::test]
async fn packet_tcp_refuses_reserved_mark_before_legacy_socket_dial() -> anyhow::Result<()> {
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let (mut wire, flow) = Wire::connect(upstream.local_addr()?)?;
    let plane = plane(config())?;
    let handle = plane.spawn_handle();
    let mut routing = honk_config::routing::RoutingConfig::default();
    routing.default_outbound = "direct".into();
    routing.default_mark = Some(honk_ebpf_common::CLASSIFIED_MARK);
    *handle.router.write().await = Router::from_config(&routing)?;
    let serving = tokio::spawn(async move { handle.serve_packet_connection(flow).await });
    wire.settle(&serving).await?;
    assert!(serving.await?.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), upstream.accept())
            .await
            .is_err()
    );
    wire.finish().await;
    Ok(())
}

#[tokio::test]
async fn packet_tcp_routes_real_loopback_and_keeps_close_until_output_release() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(20), async {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let upstream = TcpListener::bind(bind).await?;
            let (mut wire, flow) = Wire::connect(upstream.local_addr()?)?;
            let plane = plane(config())?;
            let handle = plane.spawn_handle();
            handle.connection_tracker.enable();
            let worker = handle.clone();
            let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
            let (mut server, _) =
                tokio::time::timeout(Duration::from_secs(5), upstream.accept()).await??;
            wire.send(b"packet request");
            let mut request = [0; 14];
            server.read_exact(&mut request).await?;
            assert_eq!(&request, b"packet request");
            wire.hold_data = true;
            server.write_all(b"loopback response").await?;
            wire.until(|wire| wire.received.len() == 17).await?;
            assert_eq!(wire.received, b"loopback response");
            assert!(
                wire.qualified_rx > 0,
                "later accepted input observes the real successful winner"
            );
            assert!(wire.held.is_some());
            let connections = handle.connection_tracker.snapshot();
            assert_eq!(connections.len(), 1);
            assert_eq!(connections[0].upload, 14);
            assert_eq!(connections[0].download, 17);
            assert!(handle.tcp_flow_pins.snapshot().is_empty());
            let selected = handle
                .connection_tracker
                .snapshot_close(Some("tcp"), None, 1)
                .expect("one bounded selection")
                .pop()
                .expect("tracked packet flow");
            let request = handle.connection_tracker.start_close(selected);
            let closing = tokio::spawn(async move { request.wait().await });
            serving.abort();
            assert!(serving.await.expect_err("cancel core task").is_cancelled());
            wire.pump();
            assert_eq!(handle.connection_tracker.snapshot().len(), 1);
            assert!(
                !closing.is_finished(),
                "an exported packet is still owned by its consumer"
            );
            wire.held.take().unwrap().release();
            wire.pump();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), closing).await??,
                crate::connection_tracker::CloseOutcome::Closed
            );
            assert!(handle.connection_tracker.snapshot().is_empty());
            wire.finish().await;
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn admitted_packet_tcp_keeps_route_and_mode_after_publication() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await?;
        let (mut wire, mut flow) = Wire::connect(upstream.local_addr()?)?;
        let mut plane = plane(config())?;
        let mode = Arc::new(parking_lot::RwLock::new(crate::mode::ModeState::new(
            "Rule", "block",
        )));
        plane.set_mode_state(Arc::clone(&mode));
        let handle = plane.spawn_handle();
        let mut snapshot = handle
            .prepare_packet_routing_snapshot(
                flow.scope(),
                flow.peer_addr(),
                flow.local_addr(),
                "tcp",
                flow.dscp(),
                flow.packet_source(),
                flow.process(),
                #[cfg(feature = "native-api")]
                false,
            )
            .await?;
        snapshot.admission_final = true;
        flow.set_routing(Some(
            crate::control::packet_endpoint::EndpointAdmission::new(snapshot, &wire.budget)?,
        ));
        let mut next = config();
        next.routing.default_outbound = "block".into();
        *handle.router.write().await = Router::from_config(&next.routing)?;
        *handle.config.write().await = Arc::new(next);
        *mode.write() = crate::mode::ModeState::new("Global", "block");
        let worker = handle.clone();
        let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
        let (mut server, _) =
            tokio::time::timeout(Duration::from_secs(5), upstream.accept()).await??;
        wire.send(b"admitted");
        let mut bytes = [0; 8];
        server.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"admitted");
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
        wire.finish().await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn packet_tcp_sniffing_preserves_domain_plus_and_initial_must() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
        for (mode, must, blocked, initial) in [
            ("domain+", false, false, "traffic"),
            ("domain++", false, true, "traffic"),
            ("domain++", true, false, "traffic"),
            ("domain++", false, true, "direct"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let (mut wire, flow) = Wire::connect(listener.local_addr()?)?;
            let mut config = config();
            let direct = config
                .nodes
                .iter()
                .find(|node| node.protocol() == honk_config::types::NodeProtocol::Direct)
                .unwrap()
                .id;
            config.groups = vec![Group {
                name: "traffic".into(),
                nodes: vec![direct],
                ..Default::default()
            }];
            config.routing.default_outbound = initial.into();
            config.global.dial_mode = mode.into();
            config.routing.rules.push(RoutingRule {
                name: "sniffed-block".into(),
                condition: RoutingCondition {
                    domain: vec!["blocked.example".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("block".into()),
                priority: 0,
                must: false,
                mark: None,
            });
            if must {
                config.routing.rules.push(RoutingRule {
                    name: "initial-must".into(),
                    condition: RoutingCondition {
                        protocol: vec!["tcp".into()],
                        ..Default::default()
                    },
                    outbound: RoutingOutbound::Simple("traffic".into()),
                    priority: 0,
                    must: true,
                    mark: None,
                });
            }
            let plane = plane(config)?;
            let handle = plane.spawn_handle();
            let worker = handle.clone();
            let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
            let request = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
            wire.send(request);
            if blocked {
                wire.until(|_| serving.is_finished())
                    .await
                    .with_context(|| format!("{mode}: blocked task completion"))?;
                serving.await??;
                assert_eq!(wire.qualified_rx, 0, "sniffed Block never marks the flow");
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), listener.accept())
                        .await
                        .is_err()
                );
            } else {
                let (mut server, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .with_context(|| {
                            format!(
                                "{mode} must={must}: upstream accept; serving_finished={}",
                                serving.is_finished()
                            )
                        })??;
                let mut received = vec![0; request.len()];
                server.read_exact(&mut received).await?;
                assert_eq!(received, request);
                server.write_all(b"routed").await?;
                wire.until(|wire| wire.received.len() == 6)
                    .await
                    .with_context(|| format!("{mode} must={must}: response"))?;
                assert_eq!(wire.received, b"routed");
                wire.client.tcp_shutdown(wire.id).unwrap();
                server.shutdown().await?;
                wire.until(|wire| wire.eof)
                    .await
                    .with_context(|| format!("{mode} must={must}: EOF"))?;
                wire.settle(&serving)
                    .await
                    .with_context(|| format!("{mode} must={must}: retirement"))?;
                serving.await??;
            }
            assert!(handle.tcp_flow_pins.snapshot().is_empty());
            wire.finish().await;
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn packet_tcp_sniff_keeps_the_admitted_process() -> anyhow::Result<()> {
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let (mut wire, flow) = Wire::connect(upstream.local_addr()?)?;
    let mut config = config();
    config.global.dial_mode = "domain++".into();
    let name = "abcdefghijkl�猫";
    config.routing = honk_config::parser::parse_dae_config(&format!(
        "routing {{\n domain(full:allowed.example) && !pname('{name}') -> block\n pname('{name}') -> direct\n fallback: block\n}}",
    ))?.routing;
    let flow = flow.with_process_input(crate::control::netstack::ProcessMeta::test_gateway(
        417, name,
    ));
    let plane = plane(config)?;
    let handle = plane.spawn_handle();
    handle.connection_tracker.enable();
    let worker = handle.clone();
    let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
    let request = b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n";
    wire.send(request);
    let (mut server, _) = tokio::time::timeout(Duration::from_secs(5), upstream.accept()).await??;
    let mut received = [0; 64];
    server.read_exact(&mut received[..request.len()]).await?;
    assert_eq!(&received[..request.len()], request);
    let tracked = handle.connection_tracker.snapshot();
    assert_eq!(tracked.len(), 1);
    assert_eq!(tracked[0].process.as_deref(), Some(name));
    wire.client.tcp_shutdown(wire.id).unwrap();
    server.shutdown().await?;
    wire.until(|wire| wire.eof).await?;
    wire.settle(&serving).await?;
    serving.await??;
    wire.finish().await;
    Ok(())
}

#[tokio::test]
async fn packet_tcp_dns_policy_precedes_framed_controller_and_must_uses_real_proxy()
-> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
        let dns = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let socket = Arc::clone(&dns);
        let counted = Arc::clone(&calls);
        let dns_server = tokio::spawn(async move {
            let mut packet = [0; 2048];
            for _ in 0..2 {
                let (length, peer) = socket.recv_from(&mut packet).await?;
                counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                packet[2] = 0x81;
                packet[3] = 0x80;
                socket.send_to(&packet[..length], peer).await?;
            }
            Ok::<_, std::io::Error>(())
        });
        let destination = "198.51.100.53:53".parse()?;
        let query = dns_query_payload();
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        for disposition in ["block", "controller", "must"] {
            let proxy = TcpListener::bind("127.0.0.1:0").await?;
            let (mut wire, flow) = Wire::connect(destination)?;
            let mut config = config();
            config.dns.upstream = vec![honk_config::dns::DnsUpstream {
                name: "default".into(),
                address: dns.local_addr()?.to_string(),
                protocol: honk_config::types::DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            }];
            config.dns.routing.fallback = "default".into();
            if disposition == "block" {
                config.routing.default_outbound = "block".into();
            } else if disposition == "must" {
                let node =
                    canonical_socks5("dns-peer", "127.0.0.1", proxy.local_addr()?.port(), None);
                config.groups = vec![Group {
                    name: "dns-raw".into(),
                    nodes: vec![node.id],
                    ..Default::default()
                }];
                config.nodes.push(node);
                config.routing.rules.push(RoutingRule {
                    name: "dns-must".into(),
                    condition: RoutingCondition {
                        protocol: vec!["tcp".into()],
                        ..Default::default()
                    },
                    outbound: RoutingOutbound::Simple("dns-raw".into()),
                    priority: 0,
                    must: true,
                    mark: None,
                });
            }
            let plane = plane(config)?;
            plane
                .dns_controller
                .register_packet_scopes(std::slice::from_ref(&wire.scope))?;
            let handle = plane.spawn_handle();
            let worker = handle.clone();
            let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
            wire.send(&framed);
            match disposition {
                "block" => {
                    wire.until(|_| serving.is_finished()).await?;
                    serving.await??;
                    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
                    assert_eq!(wire.qualified_rx, 0);
                }
                "controller" => {
                    wire.until(|wire| wire.received.len() == framed.len())
                        .await?;
                    let mut expected = framed.clone();
                    expected[4] = 0x81;
                    expected[5] = 0x80;
                    assert_eq!(wire.received, expected);
                    wire.send(&framed);
                    wire.until(|wire| wire.received.len() == framed.len() * 2)
                        .await?;
                    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
                    wire.send(&[0, 1, 0xff]);
                    wire.until(|wire| wire.eof).await?;
                    assert_eq!(wire.received.len(), framed.len() * 2);
                    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
                    assert_eq!(
                        wire.qualified_rx, 0,
                        "per-query DNS authority never marks the stream"
                    );
                    wire.client.tcp_shutdown(wire.id).unwrap();
                    wire.settle(&serving).await?;
                    serving.await??;
                }
                "must" => {
                    let (mut server, _) =
                        tokio::time::timeout(Duration::from_secs(5), proxy.accept()).await??;
                    let mut hello = [0; 3];
                    server.read_exact(&mut hello).await?;
                    assert_eq!(hello, [5, 1, 0]);
                    server.write_all(&[5, 0]).await?;
                    let mut request = [0; 10];
                    server.read_exact(&mut request).await?;
                    assert_eq!(request, [5, 1, 0, 1, 198, 51, 100, 53, 0, 53]);
                    server.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                    let mut received = vec![0; framed.len()];
                    server.read_exact(&mut received).await?;
                    assert_eq!(received, framed);
                    server.write_all(b"raw-not-dns").await?;
                    wire.until(|wire| wire.received.len() == 11).await?;
                    assert_eq!(wire.received, b"raw-not-dns");
                    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
                    wire.client.tcp_shutdown(wire.id).unwrap();
                    server.shutdown().await?;
                    wire.until(|wire| wire.eof).await?;
                    wire.settle(&serving).await?;
                    serving.await??;
                }
                _ => unreachable!(),
            }
            assert!(handle.tcp_flow_pins.snapshot().is_empty());
            plane.dns_controller.shutdown(Duration::from_secs(1)).await;
            drop(handle);
            drop(plane);
            wire.finish().await;
        }
        tokio::time::timeout(Duration::from_secs(5), dns_server).await???;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn packet_tcp_uses_dns_learned_domain_without_a_sniffed_name() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};

        let blocked = TcpListener::bind("127.0.0.1:0").await?;
        let direct = TcpListener::bind("127.0.0.1:0").await?;
        let dns = UdpSocket::bind("127.0.0.1:0").await?;
        let mut config = config();
        config.dns.upstream = vec![honk_config::dns::DnsUpstream {
            name: "loopback".into(),
            address: dns.local_addr()?.to_string(),
            protocol: honk_config::types::DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }];
        config.dns.routing.fallback = "loopback".into();
        config.routing.rules.push(RoutingRule {
            name: "learned-block".into(),
            condition: RoutingCondition {
                domain: vec!["a.com".into()],
                port: vec![blocked.local_addr()?.port().to_string()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("block".into()),
            priority: 0,
            must: false,
            mark: None,
        });
        let (mut wire, flow) = Wire::connect("198.51.100.53:53".parse()?)?;
        let plane = plane(config)?;
        plane
            .dns_controller
            .register_packet_scopes(std::slice::from_ref(&wire.scope))?;
        let handle = plane.spawn_handle();
        let worker = handle.clone();
        let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
        let query = dns_query_payload();
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        wire.send(&framed);
        let mut response = [0; 1024];
        let (length, sender) = dns.recv_from(&mut response).await?;
        assert_eq!(
            crate::dns::forwarder::parse_dns_question(&response[..length]),
            Some(("a.com".into(), 1))
        );
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        let answer = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1];
        response[length..length + answer.len()].copy_from_slice(&answer);
        dns.send_to(&response[..length + answer.len()], sender)
            .await?;
        wire.until(|wire| {
            wire.received.len() >= 2
                && wire.received.len()
                    == usize::from(u16::from_be_bytes([wire.received[0], wire.received[1]])) + 2
        })
        .await?;
        assert_eq!(
            crate::dns::forwarder::extract_answer_ips(&wire.received[2..]),
            ["127.0.0.1".parse::<std::net::IpAddr>()?]
        );
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
        wire.pump();

        let destination = blocked.local_addr()?;
        let accepting = tokio::spawn(async move { blocked.accept().await });
        for blocked in [false, true] {
            let destination = if blocked {
                destination
            } else {
                direct.local_addr()?
            };
            wire.id = wire
                .client
                .tcp_connect(wire.now, destination)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;
            wire.received.clear();
            wire.eof = false;
            wire.pump();
            let (_, flow) = wire.scope.poll_accept().expect("numeric TCP SYN admitted");
            wire.pump();
            let worker = handle.clone();
            let serving = tokio::spawn(async move { worker.serve_packet_connection(flow).await });
            if blocked {
                wire.until(|_| serving.is_finished() || accepting.is_finished())
                    .await?;
                assert!(
                    !accepting.is_finished(),
                    "DNS-learned Block reached the fallback Direct TCP peer"
                );
                serving.await??;
            } else {
                let (mut server, _) = direct.accept().await?;
                wire.send(b"numeric-direct-control");
                let mut bytes = [0; 22];
                server.read_exact(&mut bytes).await?;
                assert_eq!(&bytes, b"numeric-direct-control");
                server.write_all(b"numeric-reply").await?;
                wire.until(|wire| wire.received.len() == 13).await?;
                assert_eq!(wire.received, b"numeric-reply");
                serving.abort();
                assert!(serving.await.unwrap_err().is_cancelled());
                wire.pump();
            }
        }
        accepting.abort();
        assert!(accepting.await.unwrap_err().is_cancelled());
        assert!(plane.ebpf.read().await.projection_map_snapshot().is_empty());
        plane.dns_controller.shutdown(Duration::from_secs(1)).await;
        drop(handle);
        drop(plane);
        wire.finish().await;
        Ok(())
    })
    .await?
}
