use super::*;
use std::time::Duration;

fn bounded(slots: usize) -> (Stack, Arc<MemoryBudget>) {
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let mut cfg = Config::new([71; 32]);
    cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
    cfg.memory_limit = 512 * 1024;
    cfg.max_flows = 4;
    cfg.shared_budget = Some(budget.clone());
    (
        Stack::new_accounted(cfg, Instant::now(), slots).unwrap(),
        budget,
    )
}

fn reusable_tombstone(stack: &mut Stack, exhausted: bool, now: Instant) -> FlowId {
    let local_ip = stack.cfg.local_v4.unwrap().into();
    let remote = "198.51.100.1:443".parse().unwrap();
    let port = Ports::new(&stack.cfg.secret).start(&stack.cfg.secret, local_ip, remote);
    let tuple = FourTuple {
        local: SocketAddr::new(local_ip, port),
        remote,
    };
    let offset = flow::ts_offset(&stack.cfg.secret, local_ip, remote.ip());
    let stamp = offset.wrapping_add(now.duration_since(stack.epoch).as_millis() as u32);
    let iss = flow::isn(&stack.cfg.secret, tuple, now.duration_since(stack.epoch));
    let id = stack.table.insert(Flow::TimeWait(TimeWait {
        tuple,
        handle_generation: 1,
        snd_nxt: iss.wrapping_sub(1),
        rcv_nxt: 200,
        max_snd_wnd: u16::MAX.into(),
        ts_recent: Some(1),
        ts_offset: offset,
        ts_last: stamp.wrapping_sub(1),
        window: 1,
        expiry: now + Duration::from_secs(60),
        ack_due: true,
    }));
    if exhausted {
        stack.table.slots[id.idx as usize].generation = 0;
    }
    id
}

#[test]
fn failed_active_floor_admission_does_not_erase_a_reusable_time_wait() {
    let (mut stack, budget) = bounded(1);
    let now = stack.epoch + Duration::from_secs(1);
    let id = reusable_tombstone(&mut stack, false, now);
    let held = budget.reserve(budget.limit() - budget.used()).unwrap();
    assert_eq!(
        stack.tcp_connect(now, "198.51.100.1:443".parse().unwrap()),
        Err(ConnectError::Memory)
    );
    assert!(stack.tcp_retained(id));
    assert_eq!(stack.table.timewait.len(), 1);
    assert!(
        matches!(&stack.table.slots[id.idx as usize].flow, Some(Flow::TimeWait(tw)) if tw.ack_due)
    );
    drop(held);
    stack.ports = Ports::new(&stack.cfg.secret);
    let next = stack
        .tcp_connect(now, "198.51.100.1:443".parse().unwrap())
        .unwrap();
    assert_eq!(next.idx, id.idx);
    assert_ne!(next.generation, id.generation);
    assert!(!stack.tcp_retained(id));
}

#[test]
fn exhausted_replacement_requires_another_funded_slot() {
    for slots in [1, 2] {
        let (mut stack, budget) = bounded(slots);
        let now = stack.epoch + Duration::from_secs(1);
        let id = reusable_tombstone(&mut stack, true, now);
        let result = stack.tcp_connect(now, "198.51.100.1:443".parse().unwrap());
        if slots == 1 {
            assert_eq!(result, Err(ConnectError::FlowLimit));
            assert!(stack.tcp_retained(id));
            assert_eq!(stack.table.timewait.len(), 1);
        } else {
            let next = result.unwrap();
            assert_ne!(next.idx, id.idx);
            assert!(!stack.tcp_retained(id));
            assert_eq!(stack.table.slots.len(), 2);
        }
        drop(stack);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn exhausted_empty_slots_count_against_the_slab_bound() {
    let (mut stack, budget) = bounded(1);
    let id = stack.udp_bind(Some(9000)).unwrap();
    stack.table.slots[id.idx as usize].generation = u32::MAX;
    stack.udp_close(FlowId {
        generation: u32::MAX,
        ..id
    });
    assert_eq!(stack.table.slots[0].generation, 0);
    assert_eq!(stack.udp_bind(Some(9001)), Err(BindError::FlowLimit));
    assert_eq!(
        stack.tcp_connect(stack.now, "198.51.100.1:443".parse().unwrap()),
        Err(ConnectError::FlowLimit)
    );
    assert_eq!(stack.table.slots.len(), 1);
    drop(stack);
    assert_eq!(budget.used(), 0);
}

fn shards(now: Instant, slots: usize) -> ([Stack; 2], Arc<MemoryBudget>, Arc<MemoryBudget>) {
    let budget = MemoryBudget::new(32 * 1024 * 1024);
    let pending = MemoryBudget::new(crate::udp_t::MAX_PENDING_BYTES);
    let stacks = std::array::from_fn(|worker| {
        let mut cfg = Config::new([73; 32]);
        cfg.mode = Mode::Transparent {
            exclude: crate::ExcludeSet::default(),
        };
        cfg.memory_limit = 512 * 1024;
        cfg.max_flows = 4;
        cfg.shared_budget = Some(Arc::clone(&budget));
        Stack::new_accounted_shard(cfg, now, slots, worker, 2, Arc::clone(&pending)).unwrap()
    });
    (stacks, budget, pending)
}

fn syn(now: Instant) -> (Stack, FlowId, Vec<u8>) {
    let mut cfg = Config::new([74; 32]);
    cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
    let mut client = Stack::new(cfg, now);
    let id = client
        .tcp_connect(now, "198.51.100.1:443".parse().unwrap())
        .unwrap();
    let mut packet = vec![0; 2000];
    let n = client.poll_transmit(now, &mut packet).unwrap();
    packet.truncate(n);
    (client, id, packet)
}

#[test]
fn deferred_realm_tcp_restores_clock_and_drop_accounting() {
    let now = Instant::now();
    let ([mut server, _], budget, _) = shards(now, 4);
    let (_, _, packet) = syn(now);
    let ingress = now + Duration::from_secs(1);
    let service = ingress + Duration::from_secs(2);
    let _ = server.receive_reported(&packet, ReceiveOptions::new(now, RxMeta::VERIFY), |_, _| {
        false
    });
    let before = server.stats();
    let charge = budget.used();
    assert_eq!(
        server.try_receive_realm_tcp(ingress, service, &packet, |_| Err("defer")),
        Err("defer")
    );
    assert_eq!(server.now, now);
    assert_eq!(server.stats(), before);
    assert_eq!(budget.used(), charge);
    assert!(server.poll_accept().is_none());
}

#[test]
fn realm_half_open_grants_only_valid_new_syns_and_releases_before_transport_tails() {
    let now = Instant::now();
    let ([mut server, other], budget, _) = shards(now, 4);
    let (mut client, client_id, packet) = syn(now);
    let baseline = budget.used();
    let mut bad = packet.clone();
    *bad.last_mut().unwrap() ^= 1;
    let mut grants = 0;
    assert_eq!(
        server
            .receive_reported(
                &bad,
                ReceiveOptions::new(now, RxMeta::VERIFY).with_realm(now, &mut |_| {
                    grants += 1;
                    true
                }),
                |_, _| true
            )
            .0,
        Rx::Dropped(DropReason::Checksum)
    );
    assert_eq!(grants, 0);
    assert_eq!(
        server
            .receive_reported(
                &packet,
                ReceiveOptions::new(now, RxMeta::VERIFY).with_realm(now, &mut |_| false),
                |_, _| true
            )
            .0,
        Rx::Dropped(DropReason::HalfOpen)
    );
    assert_eq!(budget.used(), baseline);
    let (_, report) = server.receive_reported(
        &packet,
        ReceiveOptions::new(now, RxMeta::VERIFY).with_realm(now, &mut |_| {
            grants += 1;
            true
        }),
        |_, _| true,
    );
    let ReceiveOutcome::TcpNew(id) = report.outcome else {
        panic!("valid new SYN")
    };
    server.receive_reported(
        &packet,
        ReceiveOptions::new(now, RxMeta::VERIFY).with_realm(now, &mut |_| {
            grants += 1;
            true
        }),
        |_, _| true,
    );
    assert_eq!(grants, 1);
    assert_eq!(server.poll_accept().unwrap().id, id);
    server.tcp_accept(id, crate::AcceptOpts::default()).unwrap();
    assert_eq!(server.poll_half_open_released(), None);
    let mut out = [0; 2000];
    let AccountedTransmit::Packet(tx) = server.poll_transmit_accounted(now, &mut out, false, None)
    else {
        panic!("SYN ACK")
    };
    client.receive(now, &out[..tx.len]);
    let n = client.poll_transmit(now, &mut out).unwrap();
    server.receive_reported(
        &out[..n],
        ReceiveOptions::new(now, RxMeta::VERIFY).with_realm(now, &mut |_| {
            panic!("established input cannot reserve another half-open grant")
        }),
        |_, _| true,
    );
    assert_eq!(client.tcp_state(client_id), Some(TcpState::Established));
    assert_eq!(server.poll_half_open_released(), Some(id));
    assert_eq!(server.poll_half_open_released(), None);
    assert!(server.tcp_retained(id));
    assert_eq!(server.stats().half_open, 0);
    drop((server, other));
    assert_eq!(budget.used(), 0);
}

#[test]
fn realm_release_storage_is_bounded_and_refusal_releases_the_exact_generation() {
    let now = Instant::now();
    let ([mut server, other], budget, _) = shards(now, 1);
    let (_, _, packet) = syn(now);
    let (_, report) = server.receive_reported(
        &packet,
        ReceiveOptions::new(now, RxMeta::VERIFY).with_realm(now, &mut |_| true),
        |_, _| true,
    );
    let ReceiveOutcome::TcpNew(first) = report.outcome else {
        panic!("new SYN")
    };
    server.tcp_refuse(first, crate::Refuse::Drop);
    assert_eq!(server.stats().half_open, 0);
    assert_eq!(
        server
            .receive_reported(
                &packet,
                ReceiveOptions::new(now, RxMeta::VERIFY).with_realm(now, &mut |_| {
                    panic!("full release storage must refuse before aggregate admission")
                }),
                |_, _| true
            )
            .0,
        Rx::Dropped(DropReason::Capacity)
    );
    assert_eq!(server.poll_half_open_released(), Some(first));
    let (_, report) = server.receive_reported(
        &packet,
        ReceiveOptions::new(now, RxMeta::VERIFY).with_realm(now, &mut |_| true),
        |_, _| true,
    );
    let ReceiveOutcome::TcpNew(second) = report.outcome else {
        panic!("reused tuple")
    };
    assert_ne!(first, second);
    server.tcp_refuse(second, crate::Refuse::Rst);
    assert_eq!(server.poll_half_open_released(), Some(second));
    assert_eq!(server.poll_half_open_released(), None);
    assert!(
        server.tcp_retained(second),
        "queued RST outlives the aggregate half-open grant"
    );
    drop((server, other));
    assert_eq!(budget.used(), 0);
}

#[test]
fn realm_udp_pending_bytes_charge_both_budgets_and_rollback_together() {
    let now = Instant::now();
    let (mut stacks, budget, pending) = shards(now, 4);
    let source = "198.51.100.1:443".parse().unwrap();
    let destination = "192.0.2.1:5000".parse().unwrap();
    let payload = vec![7; 60_000];
    let mut out = [0; 2000];
    let baseline = budget.used();
    for count in 0..8 {
        stacks[count % 2]
            .udp_send_from(source, destination, &payload, &mut out)
            .unwrap();
    }
    assert_eq!(pending.used(), 8 * (payload.len() + 8));
    assert_eq!(budget.used(), baseline + pending.used());
    for stack in &mut stacks {
        assert_eq!(
            stack.udp_send_from(source, destination, &payload, &mut out),
            Err(UdpError::Busy)
        );
    }
    let [first, mut second] = stacks;
    drop(first);
    assert_eq!(pending.used(), 4 * (payload.len() + 8));
    let held = budget.reserve(budget.limit() - budget.used()).unwrap();
    let before = pending.used();
    assert_eq!(
        second.udp_send_from(source, destination, &payload, &mut out),
        Err(UdpError::Busy)
    );
    assert_eq!(pending.used(), before);
    drop(held);
    second
        .udp_send_from(source, destination, &payload, &mut out)
        .unwrap();
    while matches!(
        second.poll_transmit_accounted(now, &mut out, false, None),
        AccountedTransmit::Packet(_)
    ) {}
    assert_eq!(pending.used(), 0);
    drop(second);
    assert_eq!(budget.used(), 0);
}

#[test]
fn short_fragment_yields_to_a_smaller_control_and_retries_the_original() {
    let now = Instant::now();
    let ([mut s, _], _, _) = shards(now, 4);
    let tuple = FourTuple {
        local: "198.51.100.1:443".parse().unwrap(),
        remote: "192.0.2.1:5000".parse().unwrap(),
    };
    let mut full = [0; 2000];
    let first = s
        .udp_send_from(tuple.local, tuple.remote, &[5; 3000], &mut full)
        .unwrap();
    let next_offset = wire::frag::parse(&full[..first]).unwrap().data.len();
    s.class = 3;
    s.queue_control(Control {
        tuple,
        seq: 7,
        ack: 0,
        flags: wire::tcp::RST,
        icmp: None,
        flow: None,
        source: None,
    });
    let mut small = [0; 40];
    let AccountedTransmit::Packet(tx) = s.poll_transmit_accounted(now, &mut small, false, None)
    else {
        panic!("fitting reset starved behind UDP")
    };
    assert_eq!(tx.len, 40);
    assert_eq!(wire::parse_ip(&small).unwrap().proto, wire::PROTO_TCP);
    assert!(matches!(
        s.poll_transmit_accounted(now, &mut small, false, None),
        AccountedTransmit::BufferTooSmall
    ));
    assert!(s.poll_transmit(now, &mut small).is_none());
    let n = s.poll_transmit(now, &mut full).unwrap();
    assert!(n > small.len());
    let fragment = wire::frag::parse(&full[..n]).unwrap();
    assert_eq!(fragment.proto, wire::PROTO_UDP);
    assert_eq!(fragment.offset, next_offset);
    assert!(fragment.data.iter().all(|&byte| byte == 5));
}

#[test]
fn realm_control_capacity_and_icmp_target_burst_are_not_duplicated() {
    let now = Instant::now();
    let (mut stacks, budget, _) = shards(now, 4);
    let tuple = FourTuple {
        local: "198.51.100.1:443".parse().unwrap(),
        remote: "192.0.2.1:5000".parse().unwrap(),
    };
    for stack in &mut stacks {
        for _ in 0..128 {
            stack.queue_control(Control {
                tuple,
                seq: 7,
                ack: 0,
                flags: 0,
                icmp: Some(crate::Refuse::IcmpUnreachable),
                flow: None,
                source: None,
            });
        }
        assert_eq!(stack.controls.len(), 64);
        assert_eq!(stack.stats().control_dropped, 64);
    }
    let mut icmp = crate::IcmpState::default();
    let mut out = [0; 1280];
    let mut sent = 0;
    for index in 0..128 {
        let stack = &mut stacks[index % 2];
        if !matches!(
            stack.poll_transmit_accounted(now, &mut out, true, None),
            AccountedTransmit::NeedsIcmp
        ) {
            continue;
        }
        assert!(matches!(
            stack.poll_transmit_accounted(now, &mut [], true, Some(&mut icmp)),
            AccountedTransmit::BufferTooSmall
        ));
        assert!(matches!(
            stack.poll_transmit_accounted(now, &mut out, true, None),
            AccountedTransmit::NeedsIcmp
        ));
        if matches!(
            stack.poll_transmit_accounted(now, &mut out, true, Some(&mut icmp)),
            AccountedTransmit::Packet(_)
        ) {
            sent += 1;
        }
    }
    assert_eq!(sent, 6);
    assert!(stacks.iter().all(|stack| stack.controls.is_empty()));
    drop(stacks);
    assert_eq!(budget.used(), 0);
}

#[test]
fn accounted_udp_refusal_and_ptb_share_borrowed_limiter_and_retry_contracts() {
    let now = Instant::now();
    for workers in [1, 2] {
        for (source, destination, unspecified) in [
            ("192.0.2.1:5000", "198.51.100.1:443", "0.0.0.0:5000"),
            ("[fd00::2]:5000", "[fd00::7]:443", "[::]:5000"),
        ] {
            let (source, destination, unspecified): (SocketAddr, SocketAddr, SocketAddr) = (
                source.parse().unwrap(),
                destination.parse().unwrap(),
                unspecified.parse().unwrap(),
            );
            let budget = MemoryBudget::new(32 << 20);
            let pending = MemoryBudget::new(crate::udp_t::MAX_PENDING_BYTES);
            let mut owners: Vec<_> = (0..workers)
                .map(|worker| {
                    let mut cfg = Config::new([83; 32]);
                    cfg.mode = Mode::Transparent {
                        exclude: crate::ExcludeSet::default(),
                    };
                    cfg.shared_budget = Some(Arc::clone(&budget));
                    cfg.memory_limit = 512 << 10;
                    cfg.max_flows = 4;
                    Stack::new_accounted_shard(cfg, now, 4, worker, workers, Arc::clone(&pending))
                        .unwrap()
                })
                .collect();
            let charge = budget
                .reserve(
                    crate::IcmpState::overhead_bound(crate::IcmpLimits::default()).unwrap()
                        + std::mem::size_of::<crate::IcmpState>(),
                )
                .unwrap();
            let mut icmp = crate::IcmpState::default();
            let mut original = [0; 128];
            let n = wire::udp::emit_packet(&mut original, source, destination, &[7; 24]).unwrap();
            let original = &original[..n];
            let mut out = [0; 1280];
            assert_eq!(
                owners[0].udp_refuse_with_icmp(
                    now,
                    crate::UdpRefuse::PortUnreachable,
                    original,
                    &mut [],
                    &mut icmp
                ),
                Err(UdpError::BufferTooSmall)
            );
            for index in 0..6 {
                let how = [
                    crate::UdpRefuse::PortUnreachable,
                    crate::UdpRefuse::HostUnreachable,
                    crate::UdpRefuse::AdminProhibited,
                ][index % 3];
                let n = owners[index % workers]
                    .udp_refuse_with_icmp(now, how, original, &mut out, &mut icmp)
                    .unwrap()
                    .expect("one shared six-message target burst");
                let ip = wire::parse_ip(&out[..n]).unwrap();
                let expected = if source.is_ipv4() {
                    [[3, 3], [3, 1], [3, 13]]
                } else {
                    [[1, 4], [1, 3], [1, 1]]
                };
                assert_eq!(
                    &out[ip.payload.start..ip.payload.start + 2],
                    &expected[index % 3]
                );
            }
            assert_eq!(
                owners[0].udp_refuse_with_icmp(
                    now,
                    crate::UdpRefuse::PortUnreachable,
                    original,
                    &mut out,
                    &mut icmp
                ),
                Ok(None)
            );
            assert_eq!(
                owners[0].packet_too_big_with_icmp(now, 1400, original, &mut [], &mut icmp),
                Err(UdpError::BufferTooSmall)
            );
            for owner in &mut owners {
                let n = owner
                    .packet_too_big_with_icmp(now, 1400, original, &mut out, &mut icmp)
                    .unwrap()
                    .expect("PTB is exempt from the exhausted limiter");
                let ip = wire::parse_ip(&out[..n]).unwrap();
                assert_eq!(
                    wire::icmp::parse(ip.src, ip.dst, &out[ip.payload])
                        .unwrap()
                        .unwrap()
                        .kind,
                    wire::icmp::IcmpKind::PacketTooBig { mtu: 1400 }
                );
            }
            assert_eq!(
                owners[0].udp_refuse_with_icmp(
                    now,
                    crate::UdpRefuse::PortUnreachable,
                    original,
                    &mut out,
                    &mut icmp
                ),
                Ok(None)
            );
            let mut suppressed = [0; 128];
            let n =
                wire::udp::emit_packet(&mut suppressed, unspecified, destination, &[8; 8]).unwrap();
            assert_eq!(
                owners[0].udp_refuse_with_icmp(
                    now,
                    crate::UdpRefuse::HostUnreachable,
                    &suppressed[..n],
                    &mut out,
                    &mut icmp
                ),
                Ok(None)
            );
            assert_eq!(
                owners
                    .iter()
                    .map(|owner| owner.stats().tx_packets)
                    .sum::<u64>(),
                6 + workers as u64
            );
            drop((owners, icmp, charge));
            assert_eq!(budget.used(), 0);
        }
    }
}

#[test]
fn accounted_udp_refusal_global_burst_is_shared_between_owners() {
    let now = Instant::now();
    let (mut owners, budget, _) = shards(now, 4);
    let charge = budget
        .reserve(
            crate::IcmpState::overhead_bound(crate::IcmpLimits::default()).unwrap()
                + std::mem::size_of::<crate::IcmpState>(),
        )
        .unwrap();
    let mut icmp = crate::IcmpState::default();
    let destination: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let mut original = [0; 128];
    let mut out = [0; 1280];
    for client in 1u8..=51 {
        let source = SocketAddr::new(Ipv4Addr::new(192, 0, 2, client).into(), 5000);
        let n = wire::udp::emit_packet(&mut original, source, destination, &[7; 8]).unwrap();
        let sent = owners[usize::from(client) % 2]
            .udp_refuse_with_icmp(
                now,
                crate::UdpRefuse::PortUnreachable,
                &original[..n],
                &mut out,
                &mut icmp,
            )
            .unwrap();
        assert_eq!(sent.is_some(), client <= 50);
    }
    assert_eq!(
        owners
            .iter()
            .map(|owner| owner.stats().tx_packets)
            .sum::<u64>(),
        50
    );
    drop((owners, icmp, charge));
    assert_eq!(budget.used(), 0);
}

#[test]
fn rejected_iov_preserves_queue_order_credit_and_original_handle() {
    use std::io::ErrorKind;

    for class in 0..3 {
        let (mut stack, budget) = bounded(4);
        let now = stack.epoch + Duration::from_millis(7);
        let first = stack
            .tcp_connect(now, "198.51.100.8:443".parse().unwrap())
            .unwrap();
        let second = stack
            .tcp_connect(now, "198.51.100.9:443".parse().unwrap())
            .unwrap();
        let tw = reusable_tombstone(&mut stack, false, now);
        let Some(Flow::TimeWait(state)) = &mut stack.table.slots[tw.idx as usize].flow else {
            unreachable!()
        };
        state.handle_generation = 73;
        let original = FlowId {
            idx: tw.idx,
            generation: 73,
        };
        let tuple = state.tuple;
        stack.timewait_ready.push_back(tw);
        stack.queue_control(Control {
            tuple,
            seq: 13,
            ack: 0,
            flags: wire::tcp::RST,
            icmp: None,
            flow: Some(second),
            source: None,
        });
        stack.table.slots[first.idx as usize].deficit = 37;
        stack.class = class;
        let expected_owner = [second, original, first][usize::from(class)];
        let service_at = now + Duration::from_millis(1);
        let mut previous = None;
        for error in [ErrorKind::WouldBlock, ErrorKind::BrokenPipe] {
            let before = (
                stack.now,
                stack.ready.clone(),
                stack.timewait_ready.clone(),
                stack.controls.len(),
                stack.class,
                stack.control_class,
                stack.table.tcp_retention_changed,
                stack.counters.tx_packets,
                budget.used(),
                budget.release_epoch(),
            );
            let capture = |header: &[u8], parts: &[&[u8]], tx: Transmit| {
                assert_eq!(tx.flow, Some(expected_owner));
                assert!(parts.is_empty());
                let offered = (header.to_vec(), tx);
                if let Some(previous) = &previous {
                    assert_eq!(previous, &offered);
                }
                previous = Some(offered);
                Err(error)
            };
            assert_eq!(
                stack
                    .poll_transmit_iov(service_at, 1500, TxCaps::NONE, false, None, capture)
                    .unwrap_err(),
                error
            );
            assert_eq!(
                before,
                (
                    stack.now,
                    stack.ready.clone(),
                    stack.timewait_ready.clone(),
                    stack.controls.len(),
                    stack.class,
                    stack.control_class,
                    stack.table.tcp_retention_changed,
                    stack.counters.tx_packets,
                    budget.used(),
                    budget.release_epoch()
                )
            );
            let slot = &stack.table.slots[first.idx as usize];
            assert_eq!(slot.deficit, 37);
            assert!(slot.on_tx);
            assert!(matches!(&slot.flow, Some(Flow::Tcp(t)) if t.syn_due && t.iss == t.snd_nxt));
            assert!(
                matches!(&stack.table.slots[tw.idx as usize].flow, Some(Flow::TimeWait(t)) if t.ack_due)
            );
        }
        let (bytes, expected) = previous.unwrap();
        let sent = stack.counters.tx_packets;
        let result = stack
            .poll_transmit_iov(
                service_at,
                1500,
                TxCaps::NONE,
                false,
                None,
                |header, parts, tx| {
                    assert_eq!(tx, expected);
                    assert_eq!(header, bytes);
                    assert!(parts.is_empty());
                    Ok::<(), ErrorKind>(())
                },
            )
            .unwrap();
        assert!(matches!(result, IovTransmit::Packet(tx) if tx == expected));
        assert_eq!(stack.counters.tx_packets, sent + 1);
        match class {
            0 => {
                assert!(stack.controls.is_empty());
                assert!(stack.table.tcp_retention_changed);
            }
            1 => {
                assert!(stack.timewait_ready.is_empty());
                assert!(
                    matches!(&stack.table.slots[tw.idx as usize].flow, Some(Flow::TimeWait(t)) if !t.ack_due)
                );
            }
            _ => {
                let slot = &stack.table.slots[first.idx as usize];
                assert!(
                    matches!(&slot.flow, Some(Flow::Tcp(t)) if !t.syn_due && t.snd_nxt == t.iss.wrapping_add(1))
                );
                assert_eq!(
                    slot.deficit,
                    37 + u32::from(stack.cfg.mtu) - expected.len as u32
                );
            }
        }
    }
}
