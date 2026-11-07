use super::*;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use honk_netstack::wire::{self, tcp};
use honk_netstack::{ExcludeSet, Mode};
use tokio::io::{AsyncRead, AsyncWrite};

mod progress;

fn config() -> Config {
    let mut cfg = Config::new([37; 32]);
    cfg.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    cfg.mtu = 1280;
    cfg.max_flows = 8;
    cfg.memory_limit = 2 << 20;
    cfg.tcp_rcv_buf_max = 4096;
    cfg.tcp_snd_buf_max = 8192;
    cfg
}

fn limits() -> RuntimeLimits {
    RuntimeLimits {
        max_slots: 8,
        control_frames: 1,
        bulk_frames: 1,
        max_waiters: 4,
    }
}

fn runtime(now: Instant) -> (PacketScope, PacketOwner, Arc<MemoryBudget>) {
    let budget = MemoryBudget::new(32 << 20);
    let (scope, owner) = PacketScope::new(config(), Arc::clone(&budget), limits(), now).unwrap();
    (scope, owner, budget)
}

fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

fn output(scope: &PacketScope) -> OutputLease {
    match scope.poll_output(&mut context()) {
        Poll::Ready(Some(output)) => output,
        other => panic!("missing actual stack output: {other:?}"),
    }
}

fn segment(client: SocketAddr, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let dst: SocketAddr = if client.is_ipv6() {
        "[2001:db8::9]:443"
    } else {
        "203.0.113.9:443"
    }
    .parse()
    .unwrap();
    let mut bytes = vec![0; payload.len() + 100];
    let n = tcp::emit_packet(
        &mut bytes,
        client.ip(),
        dst.ip(),
        &tcp::Header {
            src_port: client.port(),
            dst_port: dst.port(),
            seq,
            ack,
            flags,
            window: 60000,
            urgent: 0,
            options: tcp::Options::default(),
        },
        [payload, &[]],
    )
    .unwrap();
    bytes.truncate(n);
    bytes
}

fn decode(output: &OutputLease) -> (tcp::Header, Vec<u8>) {
    let ip = wire::parse_ip(output.packet()).unwrap();
    assert_eq!(ip.proto, wire::PROTO_TCP);
    let tcp = &output.packet()[ip.payload];
    assert!(tcp::verify_checksum(ip.src, ip.dst, tcp));
    let (header, offset) = tcp::parse(tcp).unwrap();
    (header, tcp[offset..].to_vec())
}

fn handshake(scope: &PacketScope, now: Instant, client: SocketAddr, seq: u32) -> (FlowIo, u32) {
    assert_eq!(
        scope.receive(&segment(client, seq, 0, tcp::SYN, &[]), now),
        Rx::Consumed
    );
    let (syn, io) = scope.poll_accept().expect("new passive TCP flow");
    assert_eq!(syn.client, client);
    assert_eq!(syn.original_dst, "203.0.113.9:443".parse().unwrap());
    assert_eq!(syn.dscp, 0);
    assert_eq!(io.scope(), scope.scope());
    assert_eq!(io.local_addr(), syn.original_dst);
    assert_eq!(io.peer_addr(), client);
    assert_eq!(io.dscp(), syn.dscp);
    scope.drive(now);
    let reply = output(scope);
    assert_eq!(reply.flow_id(), Some(syn.id));
    assert_eq!(reply.class(), TxClass::Control);
    let (header, payload) = decode(&reply);
    assert_eq!(header.flags & (tcp::SYN | tcp::ACK), tcp::SYN | tcp::ACK);
    assert_eq!(header.ack, seq + 1);
    assert!(payload.is_empty());
    let server_seq = header.seq.wrapping_add(1);
    reply.release();
    assert_eq!(
        scope.receive(&segment(client, seq + 1, server_seq, tcp::ACK, &[]), now),
        Rx::Consumed
    );
    (io, server_seq)
}

#[test]
fn flow_io_retains_the_first_admitted_syn_dscp_for_both_families() {
    for client in ["10.0.0.2:40000", "[fd00::2]:40000"] {
        let client: SocketAddr = client.parse().unwrap();
        for dscp in [0, 46] {
            let now = Instant::now();
            let (scope, _owner, _) = runtime(now);
            let mut first = segment(client, 100, 0, tcp::SYN, &[]);
            let mut retry = first.clone();
            for (packet, value) in [(&mut first, dscp), (&mut retry, 46 - dscp)] {
                let traffic_class = value << 2 | 3;
                if client.is_ipv6() {
                    packet[0] = 0x60 | traffic_class >> 4;
                    packet[1] = traffic_class << 4;
                } else {
                    packet[1] = traffic_class;
                    packet[10..12].fill(0);
                    let checksum = wire::checksum::checksum(&packet[..20]);
                    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
                }
            }
            let mut forged = retry.clone();
            forged[wire::ip_header_len(client.is_ipv6()) + 16] ^= 1;
            assert_eq!(
                scope.receive(&forged, now),
                Rx::Dropped(DropReason::Checksum)
            );
            assert!(scope.poll_accept().is_none());
            assert_eq!(scope.receive(&first, now), Rx::Consumed);
            assert_eq!(scope.receive(&retry, now), Rx::Consumed);
            assert_eq!(
                scope.receive(&forged, now),
                Rx::Dropped(DropReason::Checksum)
            );
            let (syn, io) = scope.poll_accept().unwrap();
            assert_eq!((syn.client, syn.dscp, io.dscp()), (client, dscp, dscp));
            assert_eq!(scope.receive(&retry, now), Rx::Consumed);
            assert_eq!(
                scope.receive(&forged, now),
                Rx::Dropped(DropReason::Checksum)
            );
            assert_eq!(io.dscp(), dscp);
            assert!(scope.poll_accept().is_none());
            scope.drive(now);
            let reply = output(&scope);
            assert_eq!(decode(&reply).0.flags, tcp::SYN | tcp::ACK);
            assert_eq!(wire::parse_ip(reply.packet()).unwrap().dscp, 0);
        }
    }
}

#[test]
fn constructor_shares_the_supplied_ceiling_and_refunds_partial_failure() {
    let now = Instant::now();
    let (scope, owner, budget) = runtime(now);
    assert!(Arc::ptr_eq(&scope.budget(), &budget));
    let required = budget.used();
    assert!(required > 3 * 1280);
    drop(owner);
    drop(scope);
    assert_eq!(budget.used(), 0);

    let shared = MemoryBudget::new(required * 2 - 1);
    let (first, owner) = PacketScope::new(config(), Arc::clone(&shared), limits(), now).unwrap();
    assert_eq!(shared.used(), required);
    assert!(PacketScope::new(config(), Arc::clone(&shared), limits(), now).is_err());
    assert_eq!(shared.used(), required);
    drop(owner);
    drop(first);
    assert_eq!(shared.used(), 0);
}

#[test]
fn closed_admission_keeps_established_reads_writes_and_original_addresses() {
    let now = Instant::now();
    let (scope, _owner, _) = runtime(now);
    let client = "10.0.0.2:40000".parse().unwrap();
    let (mut io, server_seq) = handshake(&scope, now, client, 100);
    scope.close_admission();
    let stranger = "10.0.0.3:40001".parse().unwrap();
    assert!(matches!(
        scope.receive(&segment(stranger, 200, 0, tcp::SYN, &[]), now),
        Rx::Dropped(_)
    ));
    assert!(scope.poll_accept().is_none());
    assert_eq!(
        scope.receive(&segment(client, 101, server_seq, tcp::ACK, b"hello"), now),
        Rx::Consumed
    );
    let mut bytes = [0; 5];
    let mut read = tokio::io::ReadBuf::new(&mut bytes);
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_read(&mut context(), &mut read),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(read.filled(), b"hello");
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), b"world"),
        Poll::Ready(Ok(5))
    ));
    scope.drive(now + Duration::from_millis(50));
    let reply = loop {
        let packet = output(&scope);
        if !decode(&packet).1.is_empty() {
            break packet;
        }
        packet.release();
    };
    assert_eq!(decode(&reply).1, b"world");
    let ip = wire::parse_ip(reply.packet()).unwrap();
    assert_eq!(ip.src, io.local_addr().ip());
    assert_eq!(ip.dst, io.peer_addr().ip());
}

#[test]
fn saturated_bulk_keeps_control_progress_and_batch_returns_exact_scopes() {
    let now = Instant::now();
    let (scope, _owner, _) = runtime(now);
    let client = "10.0.0.2:40000".parse().unwrap();
    let (mut io, server_seq) = handshake(&scope, now, client, 100);
    let old = io.flow_id();
    let destination = io.local_addr();
    let retired = Arc::new(AtomicUsize::new(0));
    let callback_scope = scope.clone();
    let observed = Arc::clone(&retired);
    io.set_retirement_callback(move || {
        // A callback can enter the scope: it must not run under the runtime mutex.
        let _ = callback_scope.stats();
        observed.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), b"old-output"),
        Poll::Ready(Ok(10))
    ));
    scope.drive(now);
    let mut old_output = output(&scope);
    assert_eq!(old_output.class(), TxClass::Bulk);
    assert_eq!(old_output.flow_id(), Some(old));
    let original_bytes = old_output.packet().to_vec();

    assert_eq!(
        scope.receive(&segment(client, 101, server_seq, tcp::ACK, b"data"), now),
        Rx::Consumed
    );
    scope.drive(now + Duration::from_millis(50));
    let ack = output(&scope);
    assert_eq!(ack.class(), TxClass::Control);
    assert_eq!(decode(&ack).0.ack, 105);
    assert!(decode(&ack).1.is_empty());
    ack.release();
    let mut retirement = io.retirement();
    io.abort();
    drop(io);
    scope.drive(now + Duration::from_millis(51));
    let reset = output(&scope);
    assert_eq!(reset.class(), TxClass::Control);
    assert_ne!(decode(&reset).0.flags & tcp::RST, 0);
    reset.release();
    assert_eq!(retired.load(Ordering::SeqCst), 0);
    assert!(
        scope.retains_tcp(client, destination),
        "exported output retains Endpoint execution after app close"
    );
    {
        let pending = retirement.wait();
        let mut pending = pin!(pending);
        assert!(pending.as_mut().poll(&mut context()).is_pending());
    }
    let (new_io, _) = handshake(&scope, now + Duration::from_millis(52), client, 900);
    assert_ne!(new_io.flow_id(), old);
    assert_eq!(old_output.packet(), original_bytes);
    let (other_scope, _other_owner, _) = runtime(now);
    let (mut other_io, _) = handshake(&other_scope, now, client, 100);
    assert_eq!(other_io.flow_id(), old, "FlowIds are local to each stack");
    assert!(matches!(
        std::pin::Pin::new(&mut other_io).poll_write(&mut context(), b"other-output"),
        Poll::Ready(Ok(12))
    ));
    other_scope.drive(now);
    let mut other_output = output(&other_scope);
    OutputLease::release_batch(&mut [Some(&mut other_output), Some(&mut old_output)]);
    drop((old_output, other_output));
    assert!(other_scope.retains_tcp(client, destination));
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    let completed = retirement.wait();
    let mut completed = pin!(completed);
    assert!(matches!(
        completed.as_mut().poll(&mut context()),
        Poll::Ready(Ok(()))
    ));
    assert!(
        scope
            .0
            .inner
            .lock()
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.id == new_io.flow_id())
    );
}

#[tokio::test]
async fn class_batch_exports_bounded_wrapped_bulk_without_consuming_control() {
    let now = Instant::now();
    let budget = MemoryBudget::new(32 << 20);
    let mut limits = limits();
    limits.bulk_frames = 3;
    let (scope, _owner) = PacketScope::new(config(), budget, limits, now).unwrap();
    let client = "10.0.0.2:40000".parse().unwrap();
    let (mut io, server_seq) = handshake(&scope, now, client, 100);
    let sender = scope.datagram_sender("203.0.113.9:53".parse().unwrap());
    for _ in 0..2 {
        sender.send_to(b"prime", client).await.unwrap();
        output(&scope).release();
    }
    assert_eq!(scope.0.inner.lock().head, 3);
    for (index, payload) in [
        b"first".as_slice(),
        b"second".as_slice(),
        b"third".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(matches!(
            std::pin::Pin::new(&mut io).poll_write(&mut context(), payload),
            Poll::Ready(Ok(n)) if n == payload.len()
        ));
        scope.drive(now + Duration::from_millis(index as u64));
    }
    assert_eq!(
        scope.receive(&segment(client, 101, server_seq, tcp::ACK, b"data"), now),
        Rx::Consumed
    );
    scope.drive(now + Duration::from_millis(50));
    let mut bulk: [Option<OutputLease>; 3] = std::array::from_fn(|_| None);
    assert_eq!(
        scope.poll_outputs_class(&mut context(), TxClass::Bulk, &mut bulk[..2]),
        Poll::Ready(Some(2))
    );
    assert!(bulk[2].is_none());
    for (output, payload) in bulk[..2]
        .iter()
        .zip([b"first".as_slice(), b"second".as_slice()])
    {
        let output = output.as_ref().unwrap();
        assert_eq!(output.class(), TxClass::Bulk);
        assert_eq!(output.flow_id(), Some(io.flow_id()));
        assert_eq!(decode(output).1, payload);
    }
    let Poll::Ready(Some(ack)) = scope.poll_output_class(&mut context(), TxClass::Control) else {
        panic!("control output stranded behind wrapped bulk");
    };
    assert_eq!(decode(&ack).0.ack, 105);
    assert!(
        scope
            .poll_output_class(&mut context(), TxClass::Control)
            .is_pending()
    );
    OutputLease::release_batch(&mut bulk.each_mut().map(Option::as_mut));
    drop(bulk);
    let last = output(&scope);
    assert_eq!(decode(&last).1, b"third");
    last.release();
    assert!(scope.poll_output(&mut context()).is_pending());
}

#[test]
fn shutdown_waits_for_handshake_connected_readiness_before_emitting_fin() {
    struct Wakes(AtomicUsize);
    impl std::task::Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let now = Instant::now();
    let (scope, _owner, _) = runtime(now);
    let client = "10.0.0.2:40000".parse().unwrap();
    assert_eq!(
        scope.receive(&segment(client, 100, 0, tcp::SYN, &[]), now),
        Rx::Consumed
    );
    let (_, mut io) = scope.poll_accept().unwrap();
    scope.drive(now);
    let synack = output(&scope);
    let header = decode(&synack).0;
    assert_eq!(header.flags, tcp::SYN | tcp::ACK);
    let server_seq = header.seq.wrapping_add(1);
    synack.release();

    let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    assert!(
        std::pin::Pin::new(&mut io)
            .poll_shutdown(&mut cx)
            .is_pending()
    );
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    scope.drive(now);
    assert!(scope.poll_output(&mut context()).is_pending());
    assert_eq!(
        scope.receive(&segment(client, 101, server_seq, tcp::ACK, &[]), now),
        Rx::Consumed
    );
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_shutdown(&mut cx),
        Poll::Ready(Ok(()))
    ));
    scope.drive(now);
    let fin = output(&scope);
    let (header, payload) = decode(&fin);
    assert_eq!(header.flags, tcp::FIN | tcp::ACK);
    assert_eq!(header.seq, server_seq);
    assert_eq!(header.ack, 101);
    assert!(payload.is_empty());
}

#[test]
fn flush_is_a_noop_until_scope_abort_discards_queued_output() {
    for owner_drop in [false, true] {
        let now = Instant::now();
        let (scope, owner, _) = runtime(now);
        let mut owner = Some(owner);
        let (mut io, _) = handshake(&scope, now, "10.0.0.2:40000".parse().unwrap(), 100);
        assert!(matches!(
            std::pin::Pin::new(&mut io).poll_write(&mut context(), b"unacknowledged"),
            Poll::Ready(Ok(14))
        ));
        scope.drive(now);
        assert_eq!(scope.0.inner.lock().queued, 1);
        assert!(matches!(
            std::pin::Pin::new(&mut io).poll_flush(&mut context()),
            Poll::Ready(Ok(()))
        ));
        scope.shutdown(false);
        assert!(matches!(
            std::pin::Pin::new(&mut io).poll_flush(&mut context()),
            Poll::Ready(Ok(()))
        ));
        if owner_drop {
            drop(owner.take());
        } else {
            scope.shutdown(true);
        }
        assert_eq!(scope.0.inner.lock().queued, 0);
        assert!(matches!(
            std::pin::Pin::new(&mut io).poll_flush(&mut context()),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted
        ));
    }
}

#[test]
fn compact_timewait_and_exported_final_ack_both_gate_retirement() {
    let now = Instant::now();
    let (scope, _owner, _) = runtime(now);
    let client = "10.0.0.2:40000".parse().unwrap();
    let (mut io, _) = handshake(&scope, now, client, 100);
    let id = io.flow_id();
    let retired = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&retired);
    io.set_retirement_callback(move || {
        observed.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_shutdown(&mut context()),
        Poll::Ready(Ok(()))
    ));
    scope.drive(now);
    let fin = output(&scope);
    let (header, _) = decode(&fin);
    assert_ne!(header.flags & tcp::FIN, 0);
    let ack = header.seq.wrapping_add(1);
    fin.release();
    assert_eq!(
        scope.receive(&segment(client, 101, ack, tcp::FIN | tcp::ACK, &[]), now),
        Rx::Consumed
    );
    scope.drive(now);
    let final_ack = output(&scope);
    assert_eq!(final_ack.flow_id(), Some(id));
    let retiring = io.retire();
    let mut retiring = pin!(retiring);
    assert!(retiring.as_mut().poll(&mut context()).is_pending());
    scope.drive(now);
    scope.drive(now + Duration::from_secs(59));
    assert!(retiring.as_mut().poll(&mut context()).is_pending());
    scope.drive(now + Duration::from_secs(61));
    assert_eq!(retired.load(Ordering::SeqCst), 0);
    assert!(retiring.as_mut().poll(&mut context()).is_pending());
    final_ack.release();
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    assert!(matches!(
        retiring.as_mut().poll(&mut context()),
        Poll::Ready(Ok(()))
    ));
}

#[tokio::test]
async fn datagram_credit_wait_is_cancel_safe_and_fragment_payload_is_accepted_once() {
    let now = Instant::now();
    let (scope, owner, budget) = runtime(now);
    let source = "203.0.113.9:53".parse().unwrap();
    let client = "10.0.0.2:40000".parse().unwrap();
    let sender = scope.datagram_sender(source);
    assert_eq!(sender.send_to(b"first", client).await.unwrap(), 5);
    let held = output(&scope);
    assert!(scope.retains_source(client.ip()));
    let original_bytes = held.packet().to_vec();
    {
        let blocked = sender.send_to(b"cancelled", client);
        let mut blocked = pin!(blocked);
        assert!(blocked.as_mut().poll(&mut context()).is_pending());
    }
    assert!(scope.0.inner.lock().waiters.iter().all(Option::is_none));
    assert_eq!(held.packet(), original_bytes);
    held.release();
    assert!(!scope.retains_source(client.ip()));
    let payload = vec![73; 4000];
    let before = budget.used();
    assert_eq!(
        sender.send_to(&payload, client).await.unwrap(),
        payload.len()
    );
    assert!(budget.used() > before);
    assert!(scope.retains_source(client.ip()));
    let receiver_budget = MemoryBudget::new(32 << 20);
    let (receiver, receiver_owner) =
        PacketScope::new(config(), receiver_budget, limits(), now).unwrap();
    let mut completed = 0;
    for _ in 0..8 {
        scope.drive(now);
        let packet = match scope.poll_output(&mut context()) {
            Poll::Ready(Some(packet)) => packet,
            Poll::Pending => break,
            Poll::Ready(None) => panic!("scope closed unexpectedly"),
        };
        assert!(scope.retains_source(client.ip()));
        if let Rx::TransparentOwned {
            src,
            dst,
            dscp,
            packet: owned,
            payload: range,
        } = receiver.receive(packet.packet(), now)
        {
            assert_eq!(src, source);
            assert_eq!(dst, client);
            assert_eq!(dscp, 0);
            assert_eq!(&owned[range], payload);
            completed += 1;
        }
        packet.release();
        if completed == 0 {
            assert!(scope.retains_source(client.ip()));
        }
    }
    assert_eq!(completed, 1);
    assert!(!scope.retains_source(client.ip()));
    scope.shutdown(true);
    receiver.shutdown(true);
    owner.run().await;
    receiver_owner.run().await;
}

#[tokio::test]
async fn joined_abort_disposes_only_queued_packets_and_waits_for_real_consumers() {
    let now = Instant::now();
    let budget = MemoryBudget::new(32 << 20);
    let (scope, owner) = PacketScope::new(
        config(),
        Arc::clone(&budget),
        RuntimeLimits {
            bulk_frames: 2,
            ..limits()
        },
        now,
    )
    .unwrap();
    let baseline = budget.used();
    let sender = scope.datagram_sender("203.0.113.9:53".parse().unwrap());
    sender
        .send_to(b"held", "10.0.0.2:40000".parse().unwrap())
        .await
        .unwrap();
    let held = output(&scope);
    let bytes = held.packet().to_vec();
    sender
        .send_to(b"queued", "10.0.0.2:40000".parse().unwrap())
        .await
        .unwrap();
    let mut owners = tokio::task::JoinSet::new();
    owners.spawn(owner.run());
    scope.shutdown(true);
    tokio::task::yield_now().await;
    assert_eq!(
        scope.0.inner.lock().queued,
        0,
        "abort disposes unexported CPU outputs"
    );
    assert!(
        owners.try_join_next().is_none(),
        "owner must wait for the consumer lease"
    );
    assert_eq!(held.packet(), bytes);
    assert!(budget.used() >= 3 * 1280);
    assert!(budget.used() <= baseline);
    drop(sender);
    drop(scope);
    assert!(
        budget.used() > 0,
        "exported bytes retain their storage charge"
    );
    held.release();
    owners.join_next().await.unwrap().unwrap();
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn owner_cancellation_keeps_callback_until_application_and_lease_release() {
    let now = Instant::now();
    let (scope, owner, budget) = runtime(now);
    let (mut io, _) = handshake(&scope, now, "10.0.0.2:40000".parse().unwrap(), 100);
    let retired = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&retired);
    io.set_retirement_callback(move || {
        observed.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), b"held"),
        Poll::Ready(Ok(4))
    ));
    scope.drive(now);
    let held = output(&scope);
    drop(owner);
    assert_eq!(retired.load(Ordering::SeqCst), 0);
    drop(io);
    assert_eq!(retired.load(Ordering::SeqCst), 0);
    drop(scope);
    assert!(budget.used() > 0);
    held.release();
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn fixed_waiter_capacity_refuses_without_serializing_or_replaying_payload() {
    let now = Instant::now();
    let budget = MemoryBudget::new(32 << 20);
    let (scope, owner) = PacketScope::new(
        config(),
        budget,
        RuntimeLimits {
            max_waiters: 1,
            ..limits()
        },
        now,
    )
    .unwrap();
    let sender = scope.datagram_sender("203.0.113.9:53".parse().unwrap());
    let client = "10.0.0.2:40000".parse().unwrap();
    sender.send_to(b"first", client).await.unwrap();
    let held = output(&scope);
    let next = sender.send_to(b"next", client);
    let mut next = pin!(next);
    assert!(next.as_mut().poll(&mut context()).is_pending());
    let refused = sender.send_to(b"refused", client);
    let mut refused = pin!(refused);
    assert!(
        matches!(refused.as_mut().poll(&mut context()), Poll::Ready(Err(error))
        if error.kind() == io::ErrorKind::OutOfMemory)
    );
    assert_eq!(scope.stats().unwrap().tx_packets, 1);
    held.release();
    assert!(matches!(
        next.as_mut().poll(&mut context()),
        Poll::Ready(Ok(4))
    ));
    assert_eq!(scope.stats().unwrap().tx_packets, 2);
    output(&scope).release();
    scope.drive(now);
    assert!(scope.poll_output(&mut context()).is_pending());
    scope.shutdown(true);
    owner.run().await;
}

#[tokio::test]
async fn joined_owner_drives_real_synack_retransmission_without_new_ingress() {
    let now = Instant::now();
    let (scope, owner, _) = runtime(now);
    let client = "10.0.0.2:40000".parse().unwrap();
    assert_eq!(
        scope.receive(&segment(client, 100, 0, tcp::SYN, &[]), now),
        Rx::Consumed
    );
    let (_, io) = scope.poll_accept().unwrap();
    let mut owners = tokio::task::JoinSet::new();
    owners.spawn(owner.run());
    let initial = tokio::time::timeout(Duration::from_secs(3), scope.next_output())
        .await
        .unwrap()
        .unwrap();
    let initial_header = decode(&initial).0;
    initial.release();
    let retransmit = tokio::time::timeout(Duration::from_secs(3), scope.next_output())
        .await
        .unwrap()
        .unwrap();
    let header = decode(&retransmit).0;
    assert_eq!(header.seq, initial_header.seq);
    assert_eq!(header.ack, initial_header.ack);
    assert_eq!(header.flags & (tcp::SYN | tcp::ACK), tcp::SYN | tcp::ACK);
    scope.shutdown(true);
    drop(io);
    retransmit.release();
    owners.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn owner_join_and_retirement_wait_include_in_progress_core_callback() {
    let now = Instant::now();
    let (scope, owner, _) = runtime(now);
    let (mut io, _) = handshake(&scope, now, "10.0.0.2:40000".parse().unwrap(), 100);
    let mut retirement = io.retirement();
    let (entered, observed) = std::sync::mpsc::sync_channel(1);
    let (finish, continued) = std::sync::mpsc::sync_channel(1);
    io.set_retirement_callback(move || {
        entered.send(()).unwrap();
        continued.recv().unwrap();
    })
    .unwrap();
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), b"held"),
        Poll::Ready(Ok(4))
    ));
    scope.drive(now);
    let held = output(&scope);
    let mut owners = tokio::task::JoinSet::new();
    owners.spawn(owner.run());
    scope.shutdown(true);
    drop(io);
    let consumer = std::thread::spawn(move || held.release());
    observed.recv().unwrap();
    tokio::task::yield_now().await;
    assert!(owners.try_join_next().is_none());
    {
        let waiting = retirement.wait();
        let mut waiting = pin!(waiting);
        assert!(waiting.as_mut().poll(&mut context()).is_pending());
    }
    finish.send(()).unwrap();
    consumer.join().unwrap();
    retirement.wait().await.unwrap();
    owners.join_next().await.unwrap().unwrap();
}

#[test]
fn validated_source_callback_holds_the_output_mutex_before_control_output() {
    let now = Instant::now();
    let (scope, _owner, _) = runtime(now);
    let client: SocketAddr = "10.0.0.2:40000".parse().unwrap();
    let mut observed = None;
    let (rx, receipt) = scope.receive_with_source(
        &segment(client, 100, 700, tcp::ACK, &[]),
        now,
        false,
        |source, _| {
            assert!(
                scope.0.inner.try_lock().is_none(),
                "an output consumer must not pass the receipt callback"
            );
            observed = Some(source);
            true
        },
    );
    let expected = honk_netstack::ValidatedSource {
        src: client,
        dst: "203.0.113.9:443".parse().unwrap(),
        protocol: wire::PROTO_TCP,
        tcp_flags: Some(tcp::ACK),
    };
    assert_eq!(observed, Some(expected));
    assert_eq!(receipt, Some(expected));
    assert_eq!(
        rx,
        Rx::Dropped(DropReason::NoFlow),
        "receipt is not accepted-child or handshake evidence"
    );
    scope.drive(now);
    let reset = output(&scope);
    assert_eq!(decode(&reset).0.flags, tcp::RST);
    reset.release();
}
