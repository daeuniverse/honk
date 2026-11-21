use super::*;
use crate::control::netstack::{CAPTURE_MEMORY, DirectRelayFence, capture_realm};
use honk_netstack::FlowId;
use std::future::poll_fn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Handle};

async fn drive<F: Future>(driver: &mut PacketDriver, operation: F) -> F::Output {
    let mut operation = std::pin::pin!(operation);
    poll_fn(|cx| {
        driver.service(cx, Instant::now());
        operation.as_mut().poll(cx)
    })
    .await
}

fn receive_segment(
    scope: &PacketScope,
    client: SocketAddr,
    destination: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) {
    let mut packet = [0; 128];
    let length = wire::tcp::emit_packet(
        &mut packet,
        client.ip(),
        destination.ip(),
        &wire::tcp::Header {
            src_port: client.port(),
            dst_port: destination.port(),
            seq,
            ack,
            flags,
            window: 4096,
            urgent: 0,
            options: wire::tcp::Options::default(),
        },
        [payload, &[]],
    )
    .unwrap();
    assert_eq!(
        scope.receive(&packet[..length], Instant::now()),
        Rx::Consumed
    );
}

async fn exchange_byte_and_fin(
    driver: &mut PacketDriver,
    scope: &PacketScope,
    listener: &TcpListener,
    client: SocketAddr,
    flow_id: FlowId,
    initial_ack: u32,
) {
    let mut peer = drive(driver, async {
        loop {
            tokio::select! {
                biased;
                output = scope.next_output() => {
                    let output = output.expect("original flow closed before its Direct dial");
                    let ip = wire::parse_ip(output.packet()).unwrap();
                    assert_eq!(output.flow_id(), Some(flow_id));
                    let (header, _) = wire::tcp::parse(&output.packet()[ip.payload]).unwrap();
                    assert_eq!(header.flags & wire::tcp::RST, 0, "original flow reset before relaying its byte");
                    output.release();
                }
                accepted = listener.accept() => break accepted.unwrap().0,
            }
        }
    })
    .await;
    let destination = listener.local_addr().unwrap();
    // An unread upload would be aborted again during refusal cleanup before
    // the driver could emit the original reset.
    receive_segment(
        scope,
        client,
        destination,
        101,
        initial_ack,
        wire::tcp::ACK | wire::tcp::FIN,
        b"u",
    );
    let acknowledge =
        |ack| receive_segment(scope, client, destination, 103, ack, wire::tcp::ACK, b"");
    let mut byte = [0];
    peer.read_exact(&mut byte)
        .await
        .expect("original upload byte");
    assert_eq!(&byte, b"u");
    assert_eq!(
        peer.read(&mut byte).await.unwrap(),
        0,
        "original FIN with no replay"
    );
    peer.write_all(b"d").await.unwrap();
    peer.shutdown().await.unwrap();

    let mut ack = initial_ack;
    let mut downloaded = false;
    loop {
        let output = drive(driver, scope.next_output())
            .await
            .expect("original download and FIN");
        let ip = wire::parse_ip(output.packet()).unwrap();
        let segment = &output.packet()[ip.payload];
        let (header, offset) = wire::tcp::parse(segment).unwrap();
        assert_eq!(header.flags & wire::tcp::RST, 0);
        let fin = header.flags & wire::tcp::FIN != 0;
        let payload = &segment[offset..];
        if payload.is_empty() && !fin {
            output.release();
            continue;
        }
        assert_eq!(output.flow_id(), Some(flow_id));
        assert_eq!(header.seq, ack);
        if !payload.is_empty() {
            assert!(!downloaded, "replayed download");
            assert_eq!(payload, b"d");
            downloaded = true;
            ack = ack.wrapping_add(1);
        }
        output.release();
        if fin {
            assert!(downloaded, "FIN preceded the original download byte");
            acknowledge(ack.wrapping_add(1));
            break;
        }
        acknowledge(ack);
    }
}

async fn dispatch_charge(
    listener: &TcpListener,
    parked_owner: Option<&Handle>,
    headroom: Option<usize>,
) -> usize {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1280, 1, 2, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap().clone();
    let (plane, _health) = local_plane_with(|config| config.groups.clear()).await;
    assert!(plane.proxy_registry.has_stock_direct());
    let router = Arc::clone(&plane.router);
    let draining = Arc::clone(&plane.drain_tracker);
    let permit_target = Arc::clone(&plane.tcp_admission_target);
    let (endpoints, mut supervisor, mut drivers) =
        PacketEndpoints::start_driven(plane, vec![(realm, owners)], 1, None, ScopeId::HOST)
            .await
            .unwrap();
    let driver = drivers.first_mut().unwrap();
    if let Some(owner) = parked_owner {
        let sole_scope = driver.sole_owner().unwrap();
        assert!(sole_scope.same_owner(&scope));
        sole_scope
            .publish_direct_relay_runtime(owner.clone(), DirectRelayFence::new(&budget).unwrap())
            .unwrap();
    }
    drive(driver, poll_fn(|cx| supervisor.poll_ready(cx)))
        .await
        .unwrap();
    let (flow, ack) = drive(
        driver,
        established_tcp(&scope, listener.local_addr().unwrap()),
    )
    .await;
    assert_eq!(flow.scope(), scope.scope());
    assert_eq!(
        flow.direct_relay_runtime().map(|owner| owner.runtime.id()),
        parked_owner.map(Handle::id),
    );
    let client = flow.peer_addr();
    let id = flow.flow_id();
    let mut retirement = flow.retirement();
    let slots = &endpoints.shared.tcp_slots;
    let slot = Arc::clone(slots).try_acquire_owned().unwrap();
    let route_gate = router.write().await;
    let baseline = budget.used();
    let pressure = headroom.map(|bytes| budget.reserve(budget.limit() - baseline - bytes).unwrap());
    let before_dispatch = budget.used();
    endpoints.sender.send(Work::Tcp(flow, slot)).await.unwrap();
    // On this current-thread runtime the synchronous Work::Tcp arm completes
    // before the test can regain every queue slot. Keep packet service stopped
    // and routing blocked so only the funded task can change the charge.
    drop(
        endpoints
            .sender
            .reserve_many(INGRESS_CAPACITY)
            .await
            .unwrap(),
    );
    let after_dispatch = budget.used();
    let occupied_slots = permit_target.load(Ordering::Acquire) - slots.available_permits();
    drop(pressure);

    if let Some(ordinary) = headroom {
        drop(route_gate);
        exchange_byte_and_fin(driver, &scope, listener, client, id, ack).await;
        drive(driver, retirement.wait()).await.unwrap();
        assert!(scope.is_protocol_quiescent());
        assert_eq!(after_dispatch - before_dispatch, ordinary);
        assert_eq!(occupied_slots, 1);
    } else {
        assert_eq!(draining.active_count(), 1, "calibration must fund one task");
        // Cancel both calibration tasks at the routing gate, before any dial.
        endpoints.close();
        drive(driver, retirement.wait()).await.unwrap();
        drop(route_gate);
    }
    drop(retirement);
    while draining.active_count() != 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        slots.available_permits(),
        permit_target.load(Ordering::Acquire)
    );
    endpoints.close();
    let (plane, result) = drive(driver, poll_fn(|cx| supervisor.poll_join_plane(cx)))
        .await
        .unwrap();
    result.unwrap();
    endpoints.shutdown().await.unwrap();
    drop((plane, supervisor, endpoints, drivers, scope));
    assert_eq!(budget.used(), 0);
    after_dispatch - before_dispatch
}

#[test]
fn owned_packet_scoped_task_budget_refusal_relays_original_tcp_on_shared() {
    let owner = Builder::new_current_thread().enable_all().build().unwrap();
    let shared = Builder::new_current_thread().enable_all().build().unwrap();
    assert_ne!(owner.handle().id(), shared.handle().id());
    shared.block_on(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let ordinary = dispatch_charge(&listener, None, None).await;
            let scoped = dispatch_charge(&listener, Some(owner.handle()), None).await;
            assert!(
                ordinary > 0 && ordinary < scoped,
                "ordinary {ordinary}, scoped {scoped}"
            );
            dispatch_charge(&listener, Some(owner.handle()), Some(ordinary)).await;
            let listener = listener.into_std().unwrap();
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock,
                "unexpected additional Direct dial",
            );
        })
        .await
        .expect("the original Direct flow must exchange bytes and retire with the owner unpolled");
    });
}
