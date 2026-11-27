use super::*;
use honk_netstack::{BindError, ConnectError, ConstructionError, MemoryBudget};

fn config(budget: &std::sync::Arc<MemoryBudget>) -> Config {
    let mut cfg = transparent();
    cfg.memory_limit = 512 * 1024;
    cfg.max_flows = 8;
    cfg.shared_budget = Some(budget.clone());
    cfg
}

#[test]
fn construction_refuses_missing_overflow_and_unfunded_capacity_without_publication() {
    let now = Instant::now();
    assert!(matches!(
        Stack::new_accounted(transparent(), now, 1),
        Err(ConstructionError::MissingBudget)
    ));
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    assert!(matches!(
        Stack::new_accounted(config(&budget), now, usize::MAX),
        Err(ConstructionError::Overflow)
    ));
    let mut cfg = config(&budget);
    cfg.fragment_limits.max_entries = usize::MAX;
    assert!(matches!(
        Stack::new_accounted(cfg, now, 1),
        Err(ConstructionError::Overflow)
    ));
    let mut cfg = config(&budget);
    cfg.memory_limit = usize::MAX;
    assert!(matches!(
        Stack::new_accounted(cfg, now, 1),
        Err(ConstructionError::Overflow)
    ));
    assert_eq!(budget.used(), 0);
    let held = budget.reserve(budget.limit() - 1).unwrap();
    assert!(matches!(
        Stack::new_accounted(config(&budget), now, 1),
        Err(ConstructionError::Capacity)
    ));
    assert_eq!(budget.used(), held.bytes());
    drop(held);
    assert_eq!(budget.used(), 0);
    assert_eq!(Stack::new(transparent(), now).overhead_reserved(), 0);
}

#[test]
fn metadata_capacity_of_independent_stacks_uses_one_ceiling_and_refunds_on_drop() {
    let now = Instant::now();
    let probe_budget = MemoryBudget::new(8 * 1024 * 1024);
    let probe = Stack::new_accounted(config(&probe_budget), now, 8).unwrap();
    let bound = probe.overhead_reserved();
    assert!(bound >= 512 * 1024);
    assert_eq!(probe_budget.used(), bound);
    drop(probe);
    assert_eq!(probe_budget.used(), 0);
    let budget = MemoryBudget::new(bound);
    let stack = Stack::new_accounted(config(&budget), now, 8).unwrap();
    assert!(matches!(
        Stack::new_accounted(config(&budget), now, 8),
        Err(ConstructionError::Capacity)
    ));
    assert_eq!(budget.used(), bound);
    drop(stack);
    assert_eq!(budget.used(), 0);
}

#[test]
fn slab_capacity_is_shared_by_udp_and_tcp_and_free_slots_are_reused() {
    let now = Instant::now();
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let mut cfg = config(&budget);
    cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
    let mut stack = Stack::new_accounted(cfg, now, 1).unwrap();
    let udp = stack.udp_bind(Some(9000)).unwrap();
    assert_eq!(stack.udp_bind(Some(9001)), Err(BindError::FlowLimit));
    assert_eq!(
        stack.tcp_connect(now, addr(DST)),
        Err(ConnectError::FlowLimit)
    );
    let peer = Peer::new(CLIENT, DST, 1000);
    assert_eq!(
        peer.syn(&mut stack, now, 1460),
        Rx::Dropped(DropReason::Capacity)
    );
    assert!(stack.poll_accept().is_none());
    stack.udp_close(udp);
    let tcp = stack.tcp_connect(now, addr(DST)).unwrap();
    assert_ne!(tcp, udp);
    assert_eq!(stack.udp_bind(Some(9001)), Err(BindError::FlowLimit));
    stack.tcp_close(tcp);
    assert!(stack.udp_bind(Some(9001)).is_ok());
    drop(stack);
    assert_eq!(budget.used(), 0);
}

#[test]
fn closed_admission_preserves_pending_syns_existing_delivery_and_udp_replies() {
    let now = Instant::now();
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let mut stack = Stack::new_accounted(config(&budget), now, 2).unwrap();
    let mut peer = Peer::new(CLIENT, DST, 1000);
    assert_eq!(peer.syn(&mut stack, now, 1460), Rx::Consumed);
    let id = info_of(&mut stack).id;
    stack.set_accepting(false);
    assert_eq!(peer.syn(&mut stack, now, 1460), Rx::Consumed);
    assert!(stack.poll_accept().is_none());
    let other = Peer::new("10.0.0.3:40001", DST, 2000);
    assert_eq!(
        other.syn(&mut stack, now, 1460),
        Rx::Dropped(DropReason::Capacity)
    );
    stack.tcp_accept(id, AcceptOpts::default()).unwrap();
    let synack = drain(&mut stack, now).remove(0).h;
    let snd = synack.seq.wrapping_add(1);
    let stamp = synack.options.timestamps.unwrap().0;
    peer.seq += 1;
    assert_eq!(
        peer.seg(&mut stack, now, snd, ACK, stamp, b"existing"),
        Rx::Consumed
    );
    assert_eq!(stack.tcp_read(id, &mut [0; 8]), Ok(8));
    assert!(!drain(&mut stack, now).is_empty());
    assert!(
        stack
            .udp_send_from(addr(DST), peer.client, b"reply", &mut [0; 2000])
            .is_ok()
    );
    stack.tcp_shutdown(id).unwrap();
    assert!(
        drain(&mut stack, now)
            .iter()
            .any(|out| out.h.flags & FIN != 0)
    );
    stack.set_accepting(true);
    assert_eq!(other.syn(&mut stack, now, 1460), Rx::Consumed);
    assert!(stack.poll_accept().is_some());
}

#[test]
fn shared_pressure_keeps_a_funded_receive_floor_instead_of_advertising_zero() {
    let now = Instant::now();
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let mut stack = Stack::new_accounted(config(&budget), now, 1).unwrap();
    let mut peer = Peer::new(CLIENT, DST, 1000);
    assert_eq!(peer.syn(&mut stack, now, 1460), Rx::Consumed);
    let id = info_of(&mut stack).id;
    let held = budget.reserve(budget.limit() - budget.used()).unwrap();
    stack.tcp_accept(id, AcceptOpts::default()).unwrap();
    let synack = drain(&mut stack, now).remove(0).h;
    assert_eq!(synack.window, 4096);
    peer.seq += 1;
    let snd = synack.seq.wrapping_add(1);
    let stamp = synack.options.timestamps.unwrap().0;
    assert_eq!(
        peer.seg(&mut stack, now, snd, ACK, stamp, &[7; 4096]),
        Rx::Consumed
    );
    let mut read = [0; 4096];
    assert_eq!(stack.tcp_read(id, &mut read), Ok(read.len()));
    assert_eq!(read, [7; 4096]);
    assert!(drain(&mut stack, now).iter().all(|out| out.h.window > 0));
    drop(held);
    drop(stack);
    assert_eq!(budget.used(), 0);
}

#[test]
fn admission_gate_also_applies_when_a_syn_emerges_from_reassembly() {
    let now = Instant::now();
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let mut stack = Stack::new_accounted(config(&budget), now, 1).unwrap();
    let whole = build(addr(CLIENT), addr(DST), 1000, 0, SYN, opts_syn(1460), &[]);
    let ip = honk_netstack::wire::parse_ip(&whole).unwrap();
    let transport = &whole[ip.payload];
    let mut packet = [0; 2000];
    let h = fragment_header(&mut packet, 16, 0x2000);
    packet[h..h + 16].copy_from_slice(&transport[..16]);
    assert_eq!(stack.receive(now, &packet[..h + 16]), Rx::Consumed);
    stack.set_accepting(false);
    let rest = &transport[16..];
    let h = fragment_header(&mut packet, rest.len(), 2);
    packet[h..h + rest.len()].copy_from_slice(rest);
    assert_eq!(
        stack.receive(now, &packet[..h + rest.len()]),
        Rx::Dropped(DropReason::Capacity)
    );
    assert!(stack.poll_accept().is_none());
    assert_eq!(stack.stats().flows, 0);
    assert_eq!(budget.used(), stack.overhead_reserved());
    stack.set_accepting(true);
    assert_eq!(stack.receive(now, &whole), Rx::Consumed);
    assert!(stack.poll_accept().is_some());
}

fn fragment_header(packet: &mut [u8], length: usize, flags: u16) -> usize {
    let h = honk_netstack::wire::ipv4::emit(
        packet,
        "10.0.0.2".parse().unwrap(),
        "203.0.113.9".parse().unwrap(),
        honk_netstack::wire::PROTO_TCP,
        length,
    )
    .unwrap();
    packet[4..6].copy_from_slice(&17u16.to_be_bytes());
    packet[6..8].copy_from_slice(&flags.to_be_bytes());
    packet[10..12].fill(0);
    let checksum = honk_netstack::wire::checksum::checksum(&packet[..h]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    h
}

#[test]
fn time_wait_occupies_a_bounded_slot_until_expiry_without_losing_duplicate_fin_ack() {
    let now = Instant::now();
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let mut stack = Stack::new_accounted(config(&budget), now, 1).unwrap();
    let mut peer = Peer::new(CLIENT, DST, 1000);
    peer.syn(&mut stack, now, 1460);
    let id = info_of(&mut stack).id;
    stack.tcp_accept(id, AcceptOpts::default()).unwrap();
    let synack = drain(&mut stack, now).remove(0).h;
    let stamp = synack.options.timestamps.unwrap().0;
    peer.seq += 1;
    peer.seg(&mut stack, now, synack.seq.wrapping_add(1), ACK, stamp, &[]);
    stack.tcp_close(id);
    let fin = drain(&mut stack, now).remove(0).h;
    let snd = fin.seq.wrapping_add(1);
    peer.seg(&mut stack, now, snd, ACK | FIN, stamp, &[]);
    drain(&mut stack, now);
    assert_eq!(stack.stats().timewait_entries, 1);
    assert!(stack.tcp_retained(id));
    let other = Peer::new("10.0.0.3:40001", DST, 2000);
    assert_eq!(
        other.syn(&mut stack, now, 1460),
        Rx::Dropped(DropReason::Capacity)
    );
    stack.set_accepting(false);
    peer.seq = peer.seq.wrapping_sub(1);
    assert_eq!(
        peer.seg(&mut stack, now + ms(1), snd, ACK | FIN, stamp, &[]),
        Rx::Consumed
    );
    assert_eq!(drain(&mut stack, now + ms(1)).len(), 1);
    assert!(stack.tcp_retained(id));
    stack.handle_timeout(now + Duration::from_secs(61));
    assert!(!stack.tcp_retained(id));
    stack.set_accepting(true);
    assert_eq!(
        other.syn(&mut stack, now + Duration::from_secs(61), 1460),
        Rx::Consumed
    );
}

#[test]
fn accounted_completed_and_atomic_packets_outlive_stack_overhead() {
    for atomic in [false, true] {
        let now = Instant::now();
        let budget = MemoryBudget::new(8 << 20);
        let mut receiver = Stack::new_accounted(config(&budget), now, 2).unwrap();
        let overhead = receiver.overhead_reserved();
        let source = addr("[fd00::2]:40000");
        let destination = addr("[2001:db8::9]:443");
        let payload = vec![0x5a; if atomic { 7 } else { 5000 }];
        let mut owned = None;
        let mut accept = |rx| match rx {
            Rx::Consumed => {}
            Rx::TransparentOwned {
                packet,
                payload: range,
                ..
            } => {
                assert_eq!(&packet[range], payload);
                assert!(owned.replace(packet).is_none());
            }
            other => panic!("reassembly failed: {other:?}"),
        };
        let mut packet = [0; 6000];
        if atomic {
            let length =
                honk_netstack::wire::udp::emit_packet(&mut packet, source, destination, &payload)
                    .unwrap();
            let transport = packet[40..length].to_vec();
            let (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) =
                (source.ip(), destination.ip())
            else {
                unreachable!()
            };
            honk_netstack::wire::ipv6::emit(&mut packet, src, dst, 44, 8 + transport.len())
                .unwrap();
            packet[40..48].copy_from_slice(&[17, 0, 0, 0, 0, 0, 0, 7]);
            packet[48..48 + transport.len()].copy_from_slice(&transport);
            accept(receiver.receive(now, &packet[..48 + transport.len()]));
        } else {
            let mut sender = Stack::new(transparent(), now);
            let length = sender
                .udp_send_from(source, destination, &payload, &mut packet)
                .unwrap();
            accept(receiver.receive(now, &packet[..length]));
            while let Some(length) = sender.poll_transmit(now, &mut packet) {
                accept(receiver.receive(now, &packet[..length]));
            }
        }
        let owned = owned.unwrap();
        assert!(owned.charged_to(&budget));
        assert_eq!(budget.used(), overhead + owned.len());
        drop(receiver);
        assert_eq!(budget.used(), owned.len());
        drop(owned);
        assert_eq!(budget.used(), 0);
    }
}
