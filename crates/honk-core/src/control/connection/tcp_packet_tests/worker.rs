use super::*;
use crate::control::netstack::{CAPTURE_MEMORY, PacketDriver, capture_realm};
use crate::control::packet_endpoint::PacketEndpoints;
use crate::test_support::{Socks5Relay, socks5_chain, socks5_relay};
use crate::xdp::{ReturnPath, worker::PeerAuthority};
use honk_datapath::{ScopeId, buffer::TxClass};
use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

struct WorkerWire {
    endpoints: PacketEndpoints,
    driver: PacketDriver,
    peers: Arc<PeerAuthority>,
    client: Stack,
}

impl WorkerWire {
    fn pump(&mut self) -> anyhow::Result<()> {
        let now = Instant::now();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        if self.endpoints.is_closing() {
            self.driver.service_closing(&mut cx, now);
            return Ok(());
        }
        let scope = self.driver.scope();
        let path = ReturnPath {
            realm: 1,
            device: 0,
            mac: [2; 6],
            vlan_tci: [0; 2],
            vlan_proto: [0; 2],
            vlan_count: 0,
        };
        self.driver.poll_local_io(&mut cx, now)?;
        self.client.handle_timeout(now);
        let mut packet = [0; 2048];
        while let Some(len) = self.client.poll_transmit(now, &mut packet) {
            self.endpoints.receive_local_on_timed(
                &mut self.driver,
                &packet[..len],
                now,
                now,
                None,
                false,
                |source, pending| self.peers.retain(scope, source, path, now, pending),
            )?;
        }
        self.driver.service(&mut cx, now);
        for class in [TxClass::Control, TxClass::Bulk] {
            let mut batch = [None];
            while let Poll::Ready(Some(1)) =
                self.driver.poll_outputs_class(&mut cx, class, &mut batch)
            {
                let output = batch[0].take().unwrap();
                let _ = self.client.receive(now, output.packet());
                output.release();
            }
        }
        while self.client.poll_event().is_some() {}
        Ok(())
    }

    async fn driving<T>(&mut self, future: impl Future<Output = T>) -> anyhow::Result<T> {
        let mut future = std::pin::pin!(future);
        loop {
            self.pump()?;
            tokio::select! {
                result = &mut future => return Ok(result),
                () = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }
    }
}

#[derive(Clone, Copy)]
enum WorkerRoute<'a> {
    Direct,
    Chain(&'a Socks5Relay, &'a Socks5Relay),
    #[cfg(feature = "native-api")]
    DirectRefused,
}

#[tokio::test]
async fn local_worker_stock_direct_transfers_the_dialed_socket() -> anyhow::Result<()> {
    tokio::time::timeout(RELAY_WAIT, worker_route(WorkerRoute::Direct)).await?
}

#[tokio::test]
async fn local_worker_direct_leaf_relays_through_both_socks5_exits() -> anyhow::Result<()> {
    tokio::time::timeout(RELAY_WAIT, async {
        let front = socks5_relay().await;
        let land = socks5_relay().await;
        worker_route(WorkerRoute::Chain(&front, &land)).await
    })
    .await?
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn local_worker_refused_direct_relays_the_original_socket() -> anyhow::Result<()> {
    tokio::time::timeout(RELAY_WAIT, worker_route(WorkerRoute::DirectRefused)).await?
}

async fn worker_route(route: WorkerRoute<'_>) -> anyhow::Result<()> {
    let direct_attached = matches!(route, WorkerRoute::Direct);
    let exits = match route {
        WorkerRoute::Chain(front, land) => Some((front, land)),
        _ => None,
    };
    let application = TcpListener::bind("127.0.0.1:0").await?;
    let destination = application.local_addr()?;
    let mut config = config();
    select_leaf(&mut config, honk_config::config::DIRECT_NODE_ID);
    if let Some((front, land)) = exits {
        let [_, front_node, land_node] = socks5_chain(front, land);
        config.groups[0].nodes.clear();
        config.groups[0].groups.push("inner".into());
        config.groups[0].exit = Some(land_node.name.clone());
        config.groups.push(Group {
            name: "inner".into(),
            nodes: vec![honk_config::config::DIRECT_NODE_ID],
            exit: Some(front_node.name.clone()),
            ..Default::default()
        });
        config.nodes.extend([front_node, land_node]);
    }
    #[cfg(feature = "native-api")]
    {
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.allow_anonymous_loopback = true;
        config.experimental.native_api.record_flows = true;
    }
    let plane = plane(config)?;
    #[cfg(feature = "native-api")]
    let (plane, native) = {
        let mut plane = plane;
        let native = crate::native_api::observation::NativeObservation::attach(&mut plane).await;
        native.attach_for_test();
        (plane, native)
    };
    let handle = plane.spawn_handle();
    handle.connection_tracker.enable();
    #[cfg(feature = "native-api")]
    handle.connection_tracker.enable_native();
    let plan = crate::control::reload::resolve_group_outbound_plan_for_target(
        &handle.group_manager.read(),
        MEASURED_SELECTOR,
        &tcp_score_context(destination, None, IpVersion::V4),
    );
    let [selected] = plan.targets.as_slice() else {
        panic!("expected one selected target");
    };
    assert_eq!(
        selected.node.protocol(),
        honk_config::types::NodeProtocol::Direct
    );
    assert_eq!(selected.route().is_some(), exits.is_some());
    assert_eq!(
        handle
            .proxy_registry
            .can_handoff_packet_direct(&handle.runtime_registry.read(), selected),
        exits.is_none(),
        "validate Direct authorization before establishing the packet flow"
    );

    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1500, 1, 16, 1, 1, &budget)?;
    let admission = Arc::new(AtomicBool::new(false));
    realm.install_admission_fence(Arc::clone(&admission))?;
    let (endpoints, mut owner, mut drivers) =
        PacketEndpoints::start_driven(plane, vec![(realm, owners)], 4, None, ScopeId::HOST).await?;
    let mut driver = drivers.pop().unwrap();
    driver.make_local(1)?;
    let peers = PeerAuthority::new(Arc::clone(&admission), &budget)?;
    let mut client_config = honk_netstack::Config::new([61; 32]);
    client_config.local_v4 = Some("10.0.0.2".parse()?);
    let mut wire = WorkerWire {
        endpoints,
        driver,
        peers,
        client: Stack::new(client_config, Instant::now()),
    };
    wire.driving(poll_fn(|cx| owner.poll_ready(cx))).await??;
    admission.store(true, Ordering::Release);
    wire.endpoints.capture_ready()?;
    let id = wire
        .client
        .tcp_connect(Instant::now(), destination)
        .map_err(|error| anyhow::anyhow!("packet client connect: {error:?}"))?;
    #[cfg(feature = "native-api")]
    if matches!(route, WorkerRoute::DirectRefused) {
        while !wire.driver.has_submitted_direct() {
            wire.pump()?;
            tokio::task::yield_now().await;
        }
        wire.driver.close_local_direct();
    }
    let (mut upstream, _) = wire.driving(application.accept()).await??;
    let connection = loop {
        if let Some(connection) = handle.connection_tracker.snapshot().pop() {
            break connection;
        }
        wire.driving(tokio::time::sleep(Duration::from_millis(1)))
            .await?;
    };
    let source = connection.source.parse()?;
    if let Some((front, land)) = exits {
        assert_eq!(*front.requests.lock(), [land.addr]);
        assert_eq!(*land.requests.lock(), [destination]);
        assert!(!wire.driver.local_direct_attached(source, destination));
    } else if direct_attached {
        while !wire.driver.local_direct_attached(source, destination) {
            wire.driving(tokio::time::sleep(Duration::from_millis(1)))
                .await?;
        }
    }

    assert_eq!(wire.client.tcp_write(id, b"s"), Ok(1));
    assert_eq!(wire.driving(upstream.read_u8()).await??, b's');
    upstream.write_all(b"r").await?;
    let mut received = [0];
    loop {
        match wire.client.tcp_read(id, &mut received) {
            Ok(1) => break,
            Err(StreamError::WouldBlock) => {
                wire.driving(tokio::time::sleep(Duration::from_millis(1)))
                    .await?;
            }
            result => panic!("packet client read: {result:?}"),
        }
    }
    assert_eq!(&received, b"r");
    assert_eq!(
        wire.driver.local_direct_attached(source, destination),
        direct_attached
    );
    let tracker = handle
        .stats
        .outbound_tracker(MEASURED_SELECTOR, crate::stats::OutboundKind::Group);
    let bytes = tracker.snapshot();
    assert_eq!((bytes.tx_bytes, bytes.rx_bytes), (1, 1));
    #[cfg(feature = "native-api")]
    let flow_id = {
        let mut id = None;
        handle
            .connection_tracker
            .visit(|entry| id = entry.native_flow_id.clone());
        id.expect("recorded worker flow")
    };
    wire.endpoints.close();
    wire.driving(owner.run()).await??;
    assert!(handle.connection_tracker.snapshot().is_empty());
    #[cfg(feature = "native-api")]
    {
        let detail = native.core.flows.test_detail(&flow_id);
        assert!(
            detail["trace"]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| {
                    step["stage"] == "connection" && step["data"]["milestone"] == "first_reply"
                })
        );
    }
    drop((wire, handle));
    #[cfg(feature = "native-api")]
    drop(native);
    assert_eq!(budget.used(), 0);
    Ok(())
}
