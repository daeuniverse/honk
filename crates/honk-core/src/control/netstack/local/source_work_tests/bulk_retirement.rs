use super::*;
use std::pin::pin;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::task::unconstrained;

const FLOW_COUNT: usize = 1_024;
const FIRST_PORT: u16 = 40_000;
const CLIENT_NEXT: u32 = 101;
const TCP_PAYLOAD: &[u8] = b"held TCP payload";
const UDP_PAYLOAD: &[u8] = b"queued UDP reply";

struct Cancellation {
    id: FlowId,
    server_next: u32,
    retirement: FlowRetirement,
    saw_reset: bool,
}

fn client(index: usize) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 1], FIRST_PORT + index as u16))
}

fn peer_ack(
    driver: &mut PacketDriver,
    authority: &Arc<PeerAuthority>,
    client: SocketAddr,
    destination: SocketAddr,
    ack: u32,
    now: Instant,
) {
    let packet = input(client, destination, CLIENT_NEXT, ack, tcp::ACK, b"");
    let scope = driver.scope();
    let (rx, report, work) = driver
        .receive_realm_timed(&packet, now, now, &mut None, false, |source, pending| {
            authority.retain(scope, source, path(), now, pending)
        })
        .unwrap();
    assert_eq!(rx, Rx::Consumed, "ACK for {client}");
    assert!(report.taken_over && work.is_none(), "ACK for {client}");
}

fn export(
    driver: &mut PacketDriver,
    cx: &mut Context<'_>,
    class: TxClass,
) -> [Option<OutputLease>; CAPTURE_CONTROL_FRAMES] {
    let mut output = std::array::from_fn(|_| None);
    assert!(!matches!(
        driver.poll_outputs_class(cx, class, &mut output),
        Poll::Ready(None)
    ));
    output
}

fn tcp_output(lease: &OutputLease) -> (SocketAddr, SocketAddr, tcp::Header, &[u8]) {
    let packet = lease.packet();
    let ip = wire::parse_ip(packet).unwrap();
    assert_eq!(ip.proto, wire::PROTO_TCP);
    let segment = &packet[ip.payload];
    assert!(tcp::verify_checksum(ip.src, ip.dst, segment));
    let (header, data_start) = tcp::parse(segment).unwrap();
    (
        SocketAddr::new(ip.src, header.src_port),
        SocketAddr::new(ip.dst, header.dst_port),
        header,
        &segment[data_start..],
    )
}

#[tokio::test]
async fn bulk_external_cancellation_waits_for_original_outputs() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, mut owners) =
        capture_realm(1280, 1, CAPTURE_WIDE_BULK_FRAMES, 1, 1, &budget).unwrap();
    let scope = realm.owners()[0].clone();
    let owner = owners.pop().unwrap();
    let mut driver = owner.hand_off();
    driver.make_local(1).unwrap();
    let mut reclaim = Box::pin(owner.reclaim());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(reclaim.as_mut().poll(&mut cx).is_pending());

    let now = Instant::now();
    let authority = PeerAuthority::new(Arc::new(AtomicBool::new(true)), &budget).unwrap();
    let destination = SocketAddr::from(([203, 0, 113, 2], 443));
    let callbacks: Arc<[AtomicUsize; FLOW_COUNT]> =
        Arc::new(std::array::from_fn(|_| AtomicUsize::new(0)));
    let mut flows = Vec::with_capacity(FLOW_COUNT);
    let mut cancellations = Vec::with_capacity(FLOW_COUNT);
    for index in 0..FLOW_COUNT {
        let peer = client(index);
        let (flow, server_next) = accept(&mut driver, &authority, peer, destination, now);
        peer_ack(&mut driver, &authority, peer, destination, server_next, now);
        driver.finish_turn(&mut cx, now);
        assert!(
            matches!(
                pin!(flow.local().unwrap().wait_established()).poll(&mut cx),
                Poll::Ready(Ok(()))
            ),
            "handshake for {peer}"
        );
        assert!(scope.retains_tcp(peer, destination));
        let retirement = flow.retirement();
        let callbacks = Arc::clone(&callbacks);
        retirement
            .on_retired(move || {
                callbacks[index].fetch_add(1, Ordering::Relaxed);
            })
            .unwrap();
        cancellations.push(Cancellation {
            id: flow.flow_id(),
            server_next,
            retirement,
            saw_reset: false,
        });
        flows.push(flow);
    }
    assert_eq!(scope.stats().unwrap().flows, FLOW_COUNT as u32);

    {
        let mut attach = pin!(flows[0].attach_remote());
        assert!(attach.as_mut().poll(&mut cx).is_pending());
        driver.finish_turn(&mut cx, now);
        assert!(matches!(attach.poll(&mut cx), Poll::Ready(Ok(()))));
    }
    assert!(matches!(
        pin!(flows[0].write_all(TCP_PAYLOAD)).poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    driver.poll_local_io(&mut cx, now).unwrap();
    driver.service(&mut cx, now);
    let mut output = [None];
    assert!(matches!(
        driver.poll_outputs_class(&mut cx, TxClass::Bulk, &mut output),
        Poll::Ready(Some(1))
    ));
    let held_tcp = output[0].take().unwrap();
    let (from, to, data_header, data) = tcp_output(&held_tcp);
    assert_eq!((from, to), (destination, client(0)));
    assert_eq!(held_tcp.flow_id(), Some(cancellations[0].id));
    assert_eq!(data_header.seq, cancellations[0].server_next);
    assert_eq!(data, TCP_PAYLOAD);
    cancellations[0].server_next = data_header.seq.wrapping_add(data.len() as u32);

    let sender = scope.datagram_sender(SocketAddr::from(([203, 0, 113, 2], 53)));
    let udp_client = SocketAddr::from(([192, 0, 2, 2], 53_000));
    // The script polls receipts directly, so Tokio's task quota must not mask a ready reply.
    let mut replies = Vec::with_capacity(UDP_FRAMES);
    for _ in 1..CAPTURE_WIDE_BULK_FRAMES {
        let mut reply = Box::pin(unconstrained(sender.send_to(UDP_PAYLOAD, udp_client)));
        assert!(reply.as_mut().poll(&mut cx).is_pending());
        replies.push(reply);
    }
    let mut held_udp = Vec::with_capacity(CAPTURE_WIDE_BULK_FRAMES);
    for _ in 0..CAPTURE_WIDE_BULK_FRAMES.div_ceil(CAPTURE_CONTROL_FRAMES) {
        driver.service(&mut cx, now);
        held_udp.extend(
            export(&mut driver, &mut cx, TxClass::Bulk)
                .into_iter()
                .flatten(),
        );
    }
    assert_eq!(held_udp.len() + 1, CAPTURE_WIDE_BULK_FRAMES);
    assert!(
        held_udp
            .iter()
            .all(|out| out.packet().ends_with(UDP_PAYLOAD))
    );
    for mut reply in replies.drain(..) {
        assert!(matches!(
            reply.as_mut().poll(&mut cx), Poll::Ready(Ok(n)) if n == UDP_PAYLOAD.len()
        ));
    }
    for _ in 0..UDP_FRAMES {
        let mut reply = Box::pin(unconstrained(sender.send_to(UDP_PAYLOAD, udp_client)));
        assert!(reply.as_mut().poll(&mut cx).is_pending());
        replies.push(reply);
    }
    assert!(matches!(
        pin!(sender.send_to(UDP_PAYLOAD, udp_client)).poll(&mut cx),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::OutOfMemory
    ));

    for cancellation in &cancellations {
        cancellation.retirement.abort();
    }
    drop(flows);

    let mut reset_count = 0;
    let mut last_reset = None;
    let turns = FLOW_COUNT.div_ceil(BATCH) + FLOW_COUNT.div_ceil(CAPTURE_CONTROL_FRAMES);
    for _ in 0..turns {
        driver.poll_local_io(&mut cx, now).unwrap();
        driver.service(&mut cx, now);
        let resets = export(&mut driver, &mut cx, TxClass::Control);
        driver.finish_turn(&mut cx, now);
        assert!(reclaim.as_mut().poll(&mut cx).is_pending());
        for reset in resets.into_iter().flatten() {
            let (from, to, header, data) = tcp_output(&reset);
            let index = usize::from(to.port().checked_sub(FIRST_PORT).expect("client port"));
            let cancellation = cancellations.get_mut(index).expect("cancelled tuple");
            assert_eq!((from, to), (destination, client(index)));
            assert!(!cancellation.saw_reset, "duplicate RST for {to}");
            assert_eq!(reset.flow_id(), Some(cancellation.id), "RST for {to}");
            assert_eq!(header.flags, tcp::RST | tcp::ACK, "RST for {to}");
            assert_eq!(
                (header.seq, header.ack),
                (cancellation.server_next, CLIENT_NEXT),
                "RST for {to}"
            );
            assert!(data.is_empty(), "RST payload for {to}");
            assert!(!driver.local_retains_tcp(to, destination));
            assert!(scope.retains_tcp(to, destination), "exported RST for {to}");
            assert_eq!(
                callbacks[index].load(Ordering::Relaxed),
                0,
                "callback for {to}"
            );
            assert!(
                pin!(cancellation.retirement.wait())
                    .poll(&mut cx)
                    .is_pending(),
                "receipt for {to}"
            );
            cancellation.saw_reset = true;
            last_reset = Some(index);
            reset_count += 1;
            reset.release();
        }
        if reset_count == FLOW_COUNT {
            break;
        }
    }
    assert_eq!(reset_count, FLOW_COUNT, "missing RSTs");
    driver.poll_local_io(&mut cx, now).unwrap();
    driver.service(&mut cx, now);
    assert!(
        export(&mut driver, &mut cx, TxClass::Control)
            .iter()
            .all(Option::is_none)
    );
    assert!(reclaim.as_mut().poll(&mut cx).is_pending());
    for (index, cancellation) in cancellations.iter_mut().enumerate().skip(1) {
        assert_eq!(
            callbacks[index].load(Ordering::Relaxed),
            1,
            "callback for {}",
            client(index)
        );
        assert!(
            matches!(
                pin!(cancellation.retirement.wait()).poll(&mut cx),
                Poll::Ready(Ok(()))
            ),
            "receipt for {}",
            client(index)
        );
        assert!(!scope.retains_tcp(client(index), destination));
    }

    // The first flow still owns its earlier data output after its RST has returned.
    assert!(scope.retains_tcp(client(0), destination));
    assert_eq!(callbacks[0].load(Ordering::Relaxed), 0);
    assert!(
        pin!(cancellations[0].retirement.wait())
            .poll(&mut cx)
            .is_pending()
    );
    for reply in &mut replies {
        assert!(reply.as_mut().poll(&mut cx).is_pending());
    }
    held_tcp.release();
    driver.service(&mut cx, now);
    assert!(reclaim.as_mut().poll(&mut cx).is_pending());
    assert_eq!(callbacks[0].load(Ordering::Relaxed), 1);
    assert!(matches!(
        pin!(cancellations[0].retirement.wait()).poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(!scope.retains_tcp(client(0), destination));
    assert!(scope.is_protocol_quiescent());

    let mut replies = replies.into_iter();
    let mut unblocked = replies.next().unwrap();
    assert!(matches!(
        unblocked.as_mut().poll(&mut cx), Poll::Ready(Ok(n)) if n == UDP_PAYLOAD.len()
    ));
    drop(unblocked);
    held_udp.extend(
        export(&mut driver, &mut cx, TxClass::Bulk)
            .into_iter()
            .flatten(),
    );
    assert_eq!(held_udp.len(), CAPTURE_WIDE_BULK_FRAMES);

    let now = now + Duration::from_millis(1);
    // Reopen the last reset's tuple while its original retirement handle is still alive.
    let index = last_reset.unwrap();
    let peer = client(index);
    let (successor, server_next) = accept(&mut driver, &authority, peer, destination, now);
    assert_ne!(successor.flow_id(), cancellations[index].id);
    peer_ack(&mut driver, &authority, peer, destination, server_next, now);
    driver.finish_turn(&mut cx, now);
    cancellations[index].retirement.abort();
    driver.poll_local_io(&mut cx, now).unwrap();
    driver.service(&mut cx, now);
    assert!(
        export(&mut driver, &mut cx, TxClass::Control)
            .iter()
            .all(Option::is_none)
    );
    peer_ack(&mut driver, &authority, peer, destination, server_next, now);
    assert!(scope.retains_tcp(peer, destination));

    drop(successor);
    scope.shutdown(true);
    driver.service_closing(&mut cx, now);
    assert!(scope.is_protocol_quiescent());
    assert!(scope.retains_source(udp_client.ip()));
    assert!(reclaim.as_mut().poll(&mut cx).is_pending());
    for mut reply in replies {
        assert!(matches!(
            reply.as_mut().poll(&mut cx),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted
        ));
    }
    for output in held_udp {
        output.release();
    }
    driver.service_closing(&mut cx, now);
    assert!(matches!(reclaim.as_mut().poll(&mut cx), Poll::Ready(true)));
    drop(reclaim);
    assert!(pin!(owner.run()).poll(&mut cx).is_ready());
    for class in [TxClass::Control, TxClass::Bulk] {
        assert!(matches!(
            driver.poll_outputs_class(&mut cx, class, &mut output),
            Poll::Ready(None)
        ));
    }
    assert!(!scope.retains_source(udp_client.ip()));
    for (index, callbacks) in callbacks.iter().enumerate() {
        assert_eq!(
            callbacks.load(Ordering::Relaxed),
            1,
            "callback for {}",
            client(index)
        );
    }
    drop((cancellations, sender, driver, scope, realm, authority));
    assert_eq!(budget.used(), 0);
}
