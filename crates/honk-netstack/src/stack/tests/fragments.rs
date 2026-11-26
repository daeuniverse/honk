use super::*;
use crate::wire::{ipv6, udp};
use std::time::Duration;

fn terminator(now: Instant) -> Stack {
    let mut cfg = Config::new([7; 32]);
    cfg.mode = Mode::Transparent {
        exclude: crate::ExcludeSet::default(),
    };
    Stack::new(cfg, now)
}

fn fragment(next: u8, data: &[u8], offset: usize, more: bool, id: u32) -> Vec<u8> {
    let mut packet = vec![0; 48 + data.len()];
    ipv6::emit(
        &mut packet,
        "fd00::2".parse().unwrap(),
        "fd00::7".parse().unwrap(),
        44,
        8 + data.len(),
    )
    .unwrap();
    ipv6::emit_fragment_header(&mut packet[40..], next, offset, more, id).unwrap();
    packet[48..].copy_from_slice(data);
    packet
}

#[test]
fn nested_ipv6_fragment_headers_are_dropped_even_behind_extensions() {
    let now = Instant::now();
    let mut stack = terminator(now);
    let mut whole = [0; 128];
    let n = udp::emit_packet(
        &mut whole,
        "[fd00::2]:5000".parse().unwrap(),
        "[fd00::7]:53".parse().unwrap(),
        b"nested fragment headers",
    )
    .unwrap();
    let atomic = fragment(wire::PROTO_UDP, &whole[40..n], 0, false, 1);
    let Rx::TransparentOwned { packet, .. } = stack.receive(now, &atomic) else {
        panic!("atomic fragment remains a complete datagram");
    };
    assert_eq!(packet.completion_ingress(), now);
    for extensions in [false, true] {
        let mut data = Vec::new();
        if extensions {
            data.extend_from_slice(&[44, 0, 0, 0, 0, 0, 0, 0]);
        }
        data.extend_from_slice(&atomic[40..]);
        let next = if extensions { 60 } else { 44 };
        for atomic_outer in [true, false] {
            let mut stack = terminator(now);
            if atomic_outer {
                let packet = fragment(next, &data, 0, false, 2);
                assert_eq!(
                    stack.receive(now, &packet),
                    Rx::Dropped(DropReason::Fragment)
                );
            } else {
                let first = fragment(next, &data[..16], 0, true, 2);
                let last = fragment(next, &data[16..], 16, false, 2);
                assert_eq!(stack.receive(now, &first), Rx::Consumed);
                assert_eq!(stack.receive(now, &last), Rx::Dropped(DropReason::Fragment));
            }
            assert_eq!(stack.reasm.len(), 0);
            assert_eq!(stack.reasm.bytes(), 0);
            assert!(stack.poll_timeout().is_none());
        }
    }
}

#[test]
fn excluded_fragments_never_acquire_reassembly_state_or_emit_time_exceeded() {
    for (src, dst) in [
        ("10.0.0.2:5000", "203.0.113.7:53"),
        ("[fd00::2]:5000", "[fd00::7]:53"),
    ] {
        let now = Instant::now();
        let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        let budget = crate::MemoryBudget::new(20 * 1024);
        let mut exclude = crate::ExcludeSet::default();
        exclude.insert(dst.ip(), if dst.is_ipv6() { 128 } else { 32 });
        let mut cfg = Config::new([7; 32]);
        cfg.mode = Mode::Transparent { exclude };
        cfg.shared_budget = Some(budget.clone());
        let mut rx = Stack::new(cfg, now);
        let mut tx = terminator(now);
        let mut out = [0; 1500];
        let n = tx.udp_send_from(src, dst, &[7; 4000], &mut out).unwrap();
        assert_eq!(
            rx.receive(now, &out[..n]),
            Rx::Dropped(DropReason::NotForUs)
        );
        assert_eq!(rx.reasm.len(), 0);
        assert_eq!(budget.used(), 0);
        assert!(rx.poll_timeout().is_none());
        let late = now + Duration::from_secs(31);
        rx.handle_timeout(late);
        assert!(rx.poll_transmit(late, &mut out).is_none());
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn fragment_dispatch_finishes_without_entering_owner_zero_transport() {
    let now = Instant::now();
    let budget = crate::MemoryBudget::new(32 << 20);
    let pending = crate::MemoryBudget::new(crate::udp_t::MAX_PENDING_BYTES);
    let mut cfg = Config::new([81; 32]);
    cfg.mode = Mode::Transparent {
        exclude: crate::ExcludeSet::default(),
    };
    cfg.shared_budget = Some(Arc::clone(&budget));
    cfg.memory_limit = 512 << 10;
    cfg.max_flows = 4;
    let mut owner_zero =
        Stack::new_accounted_shard(cfg.clone(), now, 4, 0, 2, Arc::clone(&pending)).unwrap();
    let mut owner_one = Stack::new_accounted_shard(cfg, now, 4, 1, 2, pending).unwrap();
    let h = wire::tcp::Header {
        src_port: 5000,
        dst_port: 443,
        seq: 123,
        ack: 0,
        flags: wire::tcp::SYN,
        window: 1024,
        urgent: 0,
        options: wire::tcp::Options::default(),
    };
    let mut whole = [0; 128];
    let n = wire::tcp::emit_packet(
        &mut whole,
        "fd00::2".parse().unwrap(),
        "fd00::7".parse().unwrap(),
        &h,
        [&[], &[]],
    )
    .unwrap();
    let first = fragment(wire::PROTO_TCP, &whole[40..56], 0, true, 9);
    let last = fragment(wire::PROTO_TCP, &whole[56..n], 16, false, 9);
    assert_eq!(
        owner_one
            .reassemble_for_dispatch(now, now, &first)
            .unwrap_err()
            .reason,
        DropReason::Fragment
    );
    let first_report = owner_zero
        .reassemble_for_dispatch(now, now, &first)
        .unwrap();
    assert!(first_report.packet.is_none());
    assert!(owner_zero.retains_fragment(first_report.fragment));
    let service_at = now + Duration::from_secs(1);
    let complete_report = owner_zero
        .reassemble_for_dispatch(service_at, service_at, &last)
        .unwrap();
    assert_eq!(complete_report.fragment, first_report.fragment);
    let complete = complete_report.packet.unwrap();
    assert!(complete.charged_to(&budget));
    assert_eq!(complete.fragment_info().original_ingress, now);
    assert_eq!(complete.completion_ingress(), service_at);
    assert_eq!(complete.fragment_info(), first_report.fragment);
    assert!(!owner_zero.retains_fragment(first_report.fragment));
    assert_eq!(owner_zero.stats().flows, 0);
    assert!(owner_zero.poll_accept().is_none());
    let (_, report) = owner_one.receive_with_realm_admission(
        complete.completion_ingress(),
        service_at,
        &complete,
        RxMeta::VERIFY,
        |_| true,
        |_| true,
    );
    assert!(matches!(report.outcome, ReceiveOutcome::TcpNew(_)));
    assert_eq!(owner_one.stats().half_open, 1);
    assert_eq!(
        owner_one.poll_timeout(),
        Some(service_at + crate::MAX_DEFERRED)
    );
    drop((owner_zero, owner_one));
    assert_eq!(budget.used(), complete.len());
    drop(complete);
    assert_eq!(budget.used(), 0);
}

#[test]
fn fragment_timeout_output_receipt_keeps_exact_quote_and_resets_on_next_poll() {
    let now = Instant::now();
    for workers in [1, 2] {
        let budget = crate::MemoryBudget::new(32 << 20);
        let pending = crate::MemoryBudget::new(crate::udp_t::MAX_PENDING_BYTES);
        let mut cfg = Config::new([82; 32]);
        cfg.mode = Mode::Transparent {
            exclude: crate::ExcludeSet::default(),
        };
        cfg.shared_budget = Some(Arc::clone(&budget));
        cfg.memory_limit = 512 << 10;
        cfg.max_flows = 4;
        let mut owner = Stack::new_accounted_shard(cfg, now, 4, 0, workers, pending).unwrap();
        let suppressed = fragment(wire::PROTO_ICMPV6, &[1, 0, 0, 0, 0, 0, 0, 0], 0, true, 77);
        let first = fragment(
            wire::PROTO_UDP,
            &[0x13, 0x88, 0, 53, 0, 16, 0, 1],
            0,
            true,
            78,
        );
        let suppressed = owner
            .reassemble_for_dispatch(now, now, &suppressed)
            .unwrap()
            .fragment;
        let old = owner
            .reassemble_for_dispatch(now, now, &first)
            .unwrap()
            .fragment;
        owner.handle_timeout(now + Duration::from_secs(30));
        let service = now + Duration::from_secs(31);
        let fresh = owner
            .reassemble_for_dispatch(service, service, &first)
            .unwrap()
            .fragment;
        assert_ne!(old.incarnation, fresh.incarnation);
        let mut out = [0; 1280];
        let mut icmp = crate::IcmpState::default();
        let charge = budget
            .reserve(
                crate::IcmpState::overhead_bound(crate::IcmpLimits::default()).unwrap()
                    + std::mem::size_of::<crate::IcmpState>(),
            )
            .unwrap();
        assert!(matches!(
            owner.poll_transmit_accounted(service, &mut out, true, None),
            AccountedTransmit::NeedsIcmp
        ));
        assert_eq!(owner.take_fragment_output(), None);
        assert!(matches!(
            owner.poll_transmit_accounted(service, &mut out, true, Some(&mut icmp)),
            AccountedTransmit::Packet(_)
        ));
        assert_eq!(owner.take_fragment_output(), Some(old));
        assert_eq!(owner.take_fragment_output(), None);
        assert!(!owner.retains_fragment(suppressed));
        assert!(!owner.retains_fragment(old));
        assert!(owner.retains_fragment(fresh));
        let service = service + Duration::from_secs(30);
        owner.handle_timeout(service);
        assert!(matches!(
            owner.poll_transmit_accounted(service, &mut out, true, None),
            AccountedTransmit::NeedsIcmp
        ));
        assert!(matches!(
            owner.poll_transmit_accounted(service, &mut [], true, Some(&mut icmp)),
            AccountedTransmit::BufferTooSmall
        ));
        assert_eq!(owner.take_fragment_output(), None);
        assert!(owner.retains_fragment(fresh));
        assert!(matches!(
            owner.poll_transmit_accounted(service, &mut out, true, None),
            AccountedTransmit::NeedsIcmp
        ));
        assert!(matches!(
            owner.poll_transmit_accounted(service, &mut out, true, Some(&mut icmp)),
            AccountedTransmit::Packet(_)
        ));
        assert!(matches!(
            owner.poll_transmit_accounted(service, &mut out, true, None),
            AccountedTransmit::Idle
        ));
        assert_eq!(owner.take_fragment_output(), None);
        drop((owner, icmp, charge));
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn fragment_transport_clock_uses_latest_input_in_both_processing_orders() {
    let now = Instant::now();
    let completion = now + Duration::from_secs(27);
    let service = completion + Duration::from_secs(1);
    let mut cfg = Config::new([84; 32]);
    cfg.local_v6 = Some("fd00::2".parse().unwrap());
    let mut client = Stack::new(cfg, now);
    client
        .tcp_connect(now, "[fd00::7]:443".parse().unwrap())
        .unwrap();
    let mut whole = [0; 1500];
    let n = client.poll_transmit(now, &mut whole).unwrap();
    let ip = wire::parse_ip(&whole[..n]).unwrap();
    let data = &whole[ip.payload];
    let first = fragment(wire::PROTO_TCP, &data[..16], 0, true, 911);
    let last = fragment(wire::PROTO_TCP, &data[16..], 16, false, 911);
    for reversed in [false, true] {
        for timed in [false, true] {
            let mut receiver = terminator(now);
            let (initial, first_at, final_input, final_at) = if reversed {
                (&last, completion, &first, now)
            } else {
                (&first, now, &last, completion)
            };
            let first_rx = if timed {
                receiver
                    .receive_with_realm_admission(
                        first_at,
                        service,
                        initial,
                        RxMeta::VERIFY,
                        |_| true,
                        |_| true,
                    )
                    .0
            } else {
                receiver.receive(first_at, initial)
            };
            assert_eq!(first_rx, Rx::Consumed);
            let final_rx = if timed {
                receiver
                    .receive_with_realm_admission(
                        final_at,
                        service,
                        final_input,
                        RxMeta::VERIFY,
                        |_| true,
                        |_| true,
                    )
                    .0
            } else {
                receiver.receive(final_at, final_input)
            };
            assert_eq!(final_rx, Rx::Consumed);
            assert!(receiver.poll_accept().is_some());
            assert_eq!(
                receiver.poll_timeout(),
                Some(completion + crate::MAX_DEFERRED)
            );
        }
    }
}
