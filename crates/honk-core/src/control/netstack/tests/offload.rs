use super::*;
use honk_netstack::{Csum, RxMeta, TxCsum};
use std::pin::Pin;

#[test]
fn metadata_source_gating_preserves_lock_verification_and_rx_admission() {
    let now = Instant::now();
    let (scope, _owner, _) = runtime(now);
    let client = "10.0.0.2:40000".parse().unwrap();
    let (mut flow, server) = handshake(&scope, now, client, 100);
    flow.mark_rx_admitted();
    let mut packet = segment(client, 101, server, tcp::ACK, b"metadata");
    let start = wire::parse_ip(&packet).unwrap().payload.start;
    packet[start + 16] ^= 1;
    let meta = RxMeta {
        csum: Csum::Partial {
            start: start as u16,
            offset: 16,
        },
        gso: None,
    };
    let (rx, invalid) = scope.receive_with_source(&packet, now, false, |_, _| {
        panic!("ordinary receive must verify the checksum")
    });
    assert_eq!(rx, Rx::Dropped(DropReason::Checksum));
    assert_eq!(invalid, Default::default());
    let (rx, refused) = scope.receive_with_meta_source(&packet, meta, now, false, |_, _| {
        assert!(scope.0.inner.try_lock().is_none());
        false
    });
    assert_eq!(rx, Rx::Dropped(DropReason::NotForUs));
    assert!(refused.source.is_some());
    assert!(!refused.qualified_rx);
    let mut bytes = [0; 8];
    let mut read = tokio::io::ReadBuf::new(&mut bytes);
    assert!(
        Pin::new(&mut flow)
            .poll_read(&mut context(), &mut read)
            .is_pending()
    );
    let (rx, accepted) = scope.receive_with_meta_source(&packet, meta, now, false, |_, _| {
        assert!(scope.0.inner.try_lock().is_none());
        true
    });
    assert_eq!(rx, Rx::Consumed);
    assert_eq!(accepted.source, refused.source);
    assert!(accepted.qualified_rx);
    assert!(matches!(
        Pin::new(&mut flow).poll_read(&mut context(), &mut read),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(read.filled(), b"metadata");
}

#[test]
fn cpu_offload_capacity_is_funded_without_changing_mtu_and_follows_exported_lease() {
    let now = Instant::now();
    let (ordinary, ordinary_owner, budget) = runtime(now);
    let ordinary_bytes = budget.used();
    assert_eq!(ordinary.0.inner.lock().cpu_tx_caps, TxCaps::NONE);
    drop(ordinary_owner);
    drop(ordinary);
    assert_eq!(budget.used(), 0);
    let caps = TxCaps {
        tso4: true,
        tso6: true,
        ..TxCaps::NONE
    };
    let capacity = usize::from(u16::MAX);
    let required = ordinary_bytes + (capacity - 1280) * 2;
    let short = MemoryBudget::new(required - 1);
    assert!(
        PacketScope::new_with_output(config(), Arc::clone(&short), limits(), now, caps, capacity)
            .is_err()
    );
    assert_eq!(short.used(), 0, "failed construction refunds every reserve");
    assert!(
        PacketScope::new_with_output(config(), Arc::clone(&short), limits(), now, caps, 1279)
            .is_err()
    );
    assert_eq!(short.used(), 0);
    let budget = MemoryBudget::new(required + (2 << 20));
    let (scope, owner) =
        PacketScope::new_with_output(config(), Arc::clone(&budget), limits(), now, caps, capacity)
            .unwrap();
    assert_eq!(budget.used(), required);
    assert!(
        scope
            .0
            .inner
            .lock()
            .frames
            .iter()
            .all(|frame| { frame.as_ref().is_some_and(|bytes| bytes.len() == capacity) })
    );
    let client = "10.0.0.2:40000".parse().unwrap();
    let syn = segment_with_options(
        client,
        100,
        0,
        tcp::SYN,
        &[],
        tcp::Options {
            mss: Some(1240),
            ..Default::default()
        },
    );
    assert_eq!(scope.receive(&syn, now), Rx::Consumed);
    let (_, mut flow) = scope.poll_accept().unwrap();
    scope.drive(now);
    let synack = output(&scope);
    let (header, _) = decode(&synack);
    assert_eq!(header.options.mss, Some(1240), "logical MTU stays 1280");
    let server = header.seq.wrapping_add(1);
    synack.release();
    let now = now + Duration::from_millis(10);
    assert_eq!(
        scope.receive(&segment(client, 101, server, tcp::ACK, &[]), now),
        Rx::Consumed
    );
    let payload = [73; 8192];
    assert!(matches!(
        Pin::new(&mut flow).poll_write(&mut context(), &payload),
        Poll::Ready(Ok(8192))
    ));
    scope.drive(now);
    let held = output(&scope);
    let transmit = held.transmit();
    assert!(transmit.len > 1280 && transmit.len <= capacity);
    assert_eq!(transmit.flow, Some(flow.flow_id()));
    let gso = transmit.gso.expect("CPU caps reach the shared TCP emitter");
    assert_eq!(gso.size, 1240);
    assert_eq!(
        transmit.csum,
        TxCsum::Partial {
            start: 20,
            offset: 16
        }
    );
    let bytes = held.packet().to_vec();
    drop(owner);
    drop(flow);
    drop(scope);
    assert_eq!(held.transmit(), transmit);
    assert_eq!(held.packet(), bytes);
    assert!(
        budget.used() >= capacity * 2,
        "exported backing stays funded"
    );
    held.release();
    assert_eq!(budget.used(), 0);
}

#[test]
fn materialized_tail_probe_keeps_original_ownership_after_the_fin_ack() {
    for client in ["10.0.0.2:40000", "[fd00::2]:40000"] {
        let client: SocketAddr = client.parse().unwrap();
        let now = Instant::now();
        let budget = MemoryBudget::new(32 << 20);
        let caps = TxCaps {
            tso4: true,
            tso6: true,
            ..TxCaps::NONE
        };
        let (scope, _owner) = PacketScope::new_with_output(
            config(),
            budget,
            limits(),
            now,
            caps,
            usize::from(u16::MAX),
        )
        .unwrap();
        let options = tcp::Options {
            mss: Some(1000),
            sack_permitted: true,
            ..Default::default()
        };
        assert_eq!(
            scope.receive(
                &segment_with_options(client, 100, 0, tcp::SYN, &[], options),
                now
            ),
            Rx::Consumed
        );
        let (_, mut flow) = scope.poll_accept().unwrap();
        let id = flow.flow_id();
        let destination = flow.local_addr();
        let retired = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&retired);
        flow.set_retirement_callback(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        scope.drive(now);
        let synack = output(&scope);
        let server = decode(&synack).0.seq.wrapping_add(1);
        synack.release();
        let now = now + Duration::from_millis(10);
        assert_eq!(
            scope.receive(&segment(client, 101, server, tcp::ACK, &[]), now),
            Rx::Consumed
        );
        assert!(matches!(
            Pin::new(&mut flow).poll_write(&mut context(), b"warm"),
            Poll::Ready(Ok(4))
        ));
        scope.drive(now);
        let warm = output(&scope);
        let (header, data) = decode(&warm);
        assert_eq!(data, b"warm");
        let server = header.seq.wrapping_add(data.len() as u32);
        warm.release();
        let now = now + Duration::from_millis(10);
        assert_eq!(
            scope.receive(&segment(client, 101, server, tcp::ACK | tcp::FIN, &[]), now),
            Rx::Consumed
        );
        let mut bytes = [0; 1];
        let mut read = tokio::io::ReadBuf::new(&mut bytes);
        assert!(matches!(
            Pin::new(&mut flow).poll_read(&mut context(), &mut read),
            Poll::Ready(Ok(()))
        ));
        assert!(read.filled().is_empty());
        scope.drive(now);
        let ack = output(&scope);
        assert_eq!(decode(&ack).0.ack, 102);
        ack.release();

        let payload = [73; 2000];
        assert!(matches!(
            Pin::new(&mut flow).poll_write(&mut context(), &payload),
            Poll::Ready(Ok(2000))
        ));
        assert!(matches!(
            Pin::new(&mut flow).poll_shutdown(&mut context()),
            Poll::Ready(Ok(()))
        ));
        scope.drive(now);
        let original = output(&scope);
        let tx = original.transmit();
        assert_eq!(tx.flow, Some(id));
        assert_eq!(tx.gso.unwrap().size, 1000);
        assert!(matches!(tx.csum, TxCsum::Partial { .. }));
        let ip = wire::parse_ip(original.packet()).unwrap();
        let (fin, offset) = tcp::parse(&original.packet()[ip.payload.clone()]).unwrap();
        assert_eq!(&original.packet()[ip.payload.start + offset..], payload);
        assert_eq!(fin.flags, tcp::ACK | tcp::PSH | tcp::FIN);
        let end = fin.seq.wrapping_add(payload.len() as u32 + 1);
        original.release();

        let due = scope
            .0
            .inner
            .lock()
            .stack
            .as_ref()
            .unwrap()
            .poll_timeout()
            .unwrap();
        assert_eq!(due, now + Duration::from_millis(20));
        scope.drive(due);
        let held = output(&scope);
        let transmit = held.transmit();
        let packet = held.packet().to_vec();
        let (probe, data) = decode(&held);
        assert_eq!(transmit.flow, Some(id));
        assert_eq!(probe.flags, tcp::ACK | tcp::PSH | tcp::FIN);
        assert_eq!(probe.seq.wrapping_add(data.len() as u32 + 1), end);
        assert_eq!(data, payload[1000..]);

        // The original FIN is ACKed before the already materialized probe reaches the peer.
        assert_eq!(
            scope.receive(&segment(client, 102, end, tcp::ACK, &[]), due),
            Rx::Consumed
        );
        let retiring = flow.retire();
        let mut retiring = pin!(retiring);
        assert!(retiring.as_mut().poll(&mut context()).is_pending());
        scope.drive(due);
        assert!(
            !scope
                .0
                .inner
                .lock()
                .stack
                .as_ref()
                .unwrap()
                .tcp_retained(id)
        );
        assert!(scope.retains_tcp(client, destination));
        assert_eq!(held.transmit(), transmit);
        assert_eq!(held.packet(), packet);
        assert_eq!(retired.load(Ordering::SeqCst), 0);
        assert!(retiring.as_mut().poll(&mut context()).is_pending());

        // TIME_WAIT's ACK of that late duplicate reaches the correctly retired passive closer.
        assert_eq!(
            scope.receive(&segment(client, 102, end, tcp::ACK, &[]), due),
            Rx::Dropped(DropReason::NoFlow)
        );
        scope.drive(due);
        let reset = output(&scope);
        let (header, bytes) = decode(&reset);
        assert_eq!((header.flags, header.seq, header.ack), (tcp::RST, end, 0));
        assert!(bytes.is_empty());
        assert_eq!(reset.flow_id(), None);
        reset.release();
        assert!(retiring.as_mut().poll(&mut context()).is_pending());
        held.release();
        assert_eq!(retired.load(Ordering::SeqCst), 1);
        assert!(matches!(
            retiring.as_mut().poll(&mut context()),
            Poll::Ready(Ok(()))
        ));
        assert!(!scope.retains_tcp(client, destination));
    }
}
