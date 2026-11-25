use super::*;
use honk_ebpf_common::host::HostSourceFacts;

fn facts(cookie: u64) -> HostSourceFacts {
    HostSourceFacts {
        netns_cookie: 7,
        attachment: 11,
        socket_cookie: cookie,
        return_generation: 13,
        output_ifindex: 19,
        skb_mark: 0,
        socket_mark: 0,
        pid: 0,
        pname: [0; 16],
        flags: 1,
        stage: 1,
        family: 2,
        operation_incarnation: 23,
    }
}

#[tokio::test]
async fn raw_tun_and_canonical_gateway_preserve_full_process_names() {
    use honk_ebpf_common::host::HOST_PROCESS_PRESENT;
    use honk_ebpf_common::{ROUTING_PROCESS_MAX_LEN, TASK_COMM_LEN};

    let (scope, owner, _) = runtime(Instant::now());
    scope.prepare_host().unwrap();
    let replacements = "\u{fffd}".repeat(TASK_COMM_LEN);
    assert_eq!(replacements.len(), ROUTING_PROCESS_MAX_LEN);
    for (raw, expected) in [
        ([0xff; TASK_COMM_LEN], replacements.as_str()),
        (*b"abcdefghijkl\xff\xe7\x8c\xab", "abcdefghijkl�猫"),
    ] {
        let mut facts = facts(29);
        facts.flags |= HOST_PROCESS_PRESENT;
        facts.pid = 417;
        facts.pname = raw;
        let work = scope.hold_host_source(&facts).unwrap();
        let (tun, mark) = work.packet_input().unwrap();
        let shared = work.clone().into_shared_reply_source();
        assert_eq!(shared.optional_facts(), Some(facts));
        assert_eq!(shared.packet_input(), Some((tun, mark)));
        assert_eq!(work.facts().pname, raw);
        assert_eq!(mark, Some(facts.skb_mark));
        let gateway = ProcessMeta::test_gateway(417, expected);
        for metadata in [tun, gateway] {
            assert_eq!(metadata.name().as_deref(), Some(expected));
            assert_eq!(metadata.pid, 417);
        }
    }
    owner.shutdown().await;
}

#[test]
fn malformed_gateway_name_refuses_the_flow() {
    use honk_ebpf_common::xdp_gateway::HostFlowMeta;

    let mut meta = HostFlowMeta::default();
    meta.pname[..3].copy_from_slice("猫".as_bytes());
    for length in [1, 2, u8::MAX] {
        meta.pname_len = length;
        assert!(ProcessMeta::from_gateway(meta).is_err());
    }
    meta.pname_len = 3;
    assert_eq!(
        ProcessMeta::from_gateway(meta).unwrap().name().as_deref(),
        Some("猫")
    );
}

#[tokio::test]
async fn host_retirement_keeps_exact_socket_work_without_a_transport_or_output() {
    let (scope, owner, _) = runtime(Instant::now());
    scope.prepare_host().unwrap();
    let facts = facts(29);
    let work = scope.hold_host_source(&facts).unwrap();
    drop(work);
    owner.shutdown().await;
}

fn ingress(facts: HostSourceFacts) -> HostIngress {
    HostIngress {
        facts,
        source_horizon: Instant::now() + Duration::from_secs(5),
    }
}

fn receive(scope: &PacketScope, packet: &[u8], now: Instant, facts: HostSourceFacts) -> Rx {
    scope
        .receive_host_with_source(
            (packet, RxMeta::VERIFY),
            now,
            &ingress(facts),
            &mut None,
            false,
            |_, _, _, _| true,
        )
        .unwrap()
        .0
}

fn udp_fragments(now: Instant) -> Vec<Vec<u8>> {
    let mut stack = Stack::new(config(), now);
    let mut packet = [0; 1280];
    let n = stack
        .udp_send_from(
            "192.0.2.1:40000".parse().unwrap(),
            "198.51.100.1:443".parse().unwrap(),
            &[42; 3000],
            &mut packet,
        )
        .unwrap();
    let mut packets = vec![packet[..n].to_vec()];
    while let Some(n) = stack.poll_transmit(now, &mut packet) {
        packets.push(packet[..n].to_vec());
    }
    packets
}

#[test]
fn host_retirement_keeps_only_matching_reassembly_and_unpulled_udp_replies() {
    let now = Instant::now();
    let client: SocketAddr = "192.0.2.1:40000".parse().unwrap();
    let target: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let other = SocketAddr::new(client.ip(), client.port() + 1);
    let mut stack = Stack::new(config(), now);
    let fragments = udp_fragments(now);
    stack.receive(now, &fragments[0]);
    assert!(stack.retains_packet_obligation(client, target, wire::PROTO_UDP));
    assert!(!stack.retains_packet_obligation(client, target, wire::PROTO_TCP));
    assert!(!stack.retains_packet_obligation(target, client, wire::PROTO_UDP));
    for fragment in &fragments[1..] {
        stack.receive(now, fragment);
    }
    assert!(!stack.retains_packet_obligation(client, target, wire::PROTO_UDP));

    let mut out = [0; 1280];
    stack
        .udp_send_from(target, client, &[42; 3000], &mut out)
        .unwrap();
    assert!(stack.retains_packet_obligation(client, target, wire::PROTO_UDP));
    assert!(!stack.retains_packet_obligation(other, target, wire::PROTO_UDP));
    while stack.poll_transmit(now, &mut out).is_some() {}
    assert!(!stack.retains_packet_obligation(client, target, wire::PROTO_UDP));
}

#[test]
fn host_capture_expiry_uses_admission_clock_not_old_batch_time() {
    let now = Instant::now();
    let (scope, _owner, _) = runtime(now);
    scope.prepare_host().unwrap();
    let packet = segment("192.0.2.1:40000".parse().unwrap(), 100, 0, tcp::SYN, &[]);
    let expired = HostIngress {
        facts: facts(31),
        source_horizon: now - Duration::from_secs(1),
    };
    let result = scope.receive_host_with_source(
        (&packet, RxMeta::VERIFY),
        now - Duration::from_secs(2),
        &expired,
        &mut None,
        false,
        |_, _, _, _| panic!("expired capture reached protocol source callback"),
    );
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
    assert!(!scope.has_pending_accept());
    assert!(matches!(
        scope.receive(&packet, now),
        Rx::Dropped(DropReason::NotForUs)
    ));
}

#[test]
fn host_source_snapshots_partition_executor_selections_without_changing_live_lineage() {
    let now = Instant::now();
    let (scope, _owner, _) = runtime(now);
    scope.prepare_host().unwrap();
    let original = scope.hold_host_source(&facts(31)).unwrap();
    let same = scope.hold_host_source(&facts(31)).unwrap();
    assert_eq!(original.context(), same.context());
    let mut changed = facts(31);
    changed.skb_mark = 41;
    let changed = scope.hold_host_source(&changed).unwrap();
    assert_eq!(original.context().lineage, changed.context().lineage);
    assert_ne!(original.context().snapshot, changed.context().snapshot);
    let mut selected = facts(31);
    selected.operation_incarnation += 1;
    let selected = scope.hold_host_source(&selected).unwrap();
    assert_ne!(original.context().lineage, selected.context().lineage);
    assert_eq!(original.facts().skb_mark, 0);
    scope.prepare_endpoint().unwrap();
    assert!(scope.prepare_host().is_err());
}

#[test]
fn killed_host_reassembly_pins_identity_through_source_pressure_until_expiry() {
    let now = Instant::now();
    let budget = MemoryBudget::new(32 << 20);
    let (scope, _owner) = PacketScope::new(
        config(),
        budget,
        RuntimeLimits {
            max_slots: 1,
            ..limits()
        },
        now,
    )
    .unwrap();
    scope.prepare_host().unwrap();
    let source = facts(31);
    let original = scope.hold_host_source(&source).unwrap();
    let context = original.context();
    let packets = udp_fragments(now);
    assert!(matches!(
        receive(&scope, &packets[0], now, source),
        Rx::Consumed
    ));
    assert!(matches!(
        receive(&scope, &packets[0], now, source),
        Rx::Dropped(DropReason::Fragment)
    ));
    drop(original);
    let _second = scope.hold_host_source(&facts(32)).unwrap();
    let _third = scope.hold_host_source(&facts(33)).unwrap();
    assert_eq!(
        scope.hold_host_source(&facts(34)).err().unwrap().kind(),
        io::ErrorKind::OutOfMemory
    );
    let still_original = scope.hold_host_source(&source).unwrap();
    assert_eq!(still_original.context(), context);
    drop(still_original);
    assert!(matches!(
        receive(&scope, &packets[1], now, source),
        Rx::Dropped(DropReason::Fragment)
    ));
    scope.drive(now + Duration::from_secs(31));
    assert!(scope.hold_host_source(&facts(34)).is_ok());
    assert!(
        scope.poll_output(&mut super::context()).is_pending(),
        "tombstone cannot emit ICMP"
    );
}

#[tokio::test]
async fn host_cpu_and_generated_udp_fragments_keep_original_source_after_sender_drop() {
    let now = Instant::now();
    let budget = MemoryBudget::new(32 << 20);
    let (scope, owner) = PacketScope::new(
        config(),
        budget,
        RuntimeLimits {
            max_slots: 1,
            ..limits()
        },
        now,
    )
    .unwrap();
    scope.prepare_host().unwrap();
    let source = facts(31);
    let client = "192.0.2.1:40000".parse().unwrap();
    let destination = "198.51.100.1:443".parse().unwrap();
    let sender = scope
        .datagram_sender_for(destination, scope.hold_host_source(&source).unwrap())
        .unwrap();
    assert_eq!(sender.send_to(b"first", client).await.unwrap(), 5);
    let cpu = output(&scope);
    drop(sender);
    let second = scope.hold_host_source(&facts(32)).unwrap();
    let third = scope.hold_host_source(&facts(33)).unwrap();
    assert_eq!(
        scope.hold_host_source(&facts(34)).err().unwrap().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(cpu.host_return(), Some(source));
    cpu.release();
    let released = scope.hold_host_source(&facts(34)).unwrap();
    drop(released);

    let sender = scope
        .datagram_sender_for(destination, scope.hold_host_source(&source).unwrap())
        .unwrap();
    assert_eq!(sender.send_to(&[17; 3000], client).await.unwrap(), 3000);
    let first = output(&scope);
    assert_eq!(first.host_return(), Some(source));
    drop(sender);
    first.release();
    assert_eq!(
        scope.hold_host_source(&facts(34)).err().unwrap().kind(),
        io::ErrorKind::OutOfMemory
    );

    let mut driver = owner.hand_off();
    let mut packet = [0; 1280];
    driver.begin_turn(now);
    let direct = materialized(&mut driver, now, TxClass::Bulk, &mut packet);
    assert_eq!(direct.host_return(), Some(source));
    drop(direct);
    let last = materialized(&mut driver, now, TxClass::Bulk, &mut packet);
    assert_eq!(last.host_return(), Some(source));
    assert_eq!(
        scope.hold_host_source(&facts(34)).err().unwrap().kind(),
        io::ErrorKind::OutOfMemory
    );
    drop(last);
    let released = scope.hold_host_source(&facts(34)).unwrap();
    drop((released, second, third));
    scope.shutdown(true);
    driver.finish_turn(&mut context(), now);
}

#[test]
fn host_tcp_flow_and_control_hold_original_facts_across_foreign_input() {
    let now = Instant::now();
    let budget = MemoryBudget::new(32 << 20);
    let (scope, _owner) = PacketScope::new(
        config(),
        budget,
        RuntimeLimits {
            max_slots: 1,
            ..limits()
        },
        now,
    )
    .unwrap();
    scope.prepare_host().unwrap();
    let client = "192.0.2.1:40000".parse().unwrap();
    let source = facts(31);
    assert!(matches!(
        receive(
            &scope,
            &segment(client, 77, 900, tcp::ACK, &[]),
            now,
            source
        ),
        Rx::Dropped(DropReason::NoFlow)
    ));
    let second = scope.hold_host_source(&facts(32)).unwrap();
    let third = scope.hold_host_source(&facts(33)).unwrap();
    assert_eq!(
        scope.hold_host_source(&facts(34)).err().unwrap().kind(),
        io::ErrorKind::OutOfMemory
    );
    scope.drive(now);
    let reset = output(&scope);
    assert_eq!(reset.flow_id(), None);
    assert_eq!(reset.host_return(), Some(source));
    assert_eq!(decode(&reset).0.flags, tcp::RST);
    assert_eq!(
        scope.hold_host_source(&facts(34)).err().unwrap().kind(),
        io::ErrorKind::OutOfMemory
    );
    reset.release();
    drop(scope.hold_host_source(&facts(34)).unwrap());

    assert!(matches!(
        receive(&scope, &segment(client, 100, 0, tcp::SYN, &[]), now, source),
        Rx::Consumed
    ));
    let (syn, flow) = scope.poll_accept().unwrap();
    assert_eq!(flow.packet_source().unwrap().facts(), source);
    scope.drive(now);
    let held = output(&scope);
    let (header, _) = decode(&held);
    assert_eq!(held.flow_id(), Some(syn.id));
    assert_eq!(held.host_return(), Some(source));
    assert!(matches!(
        receive(
            &scope,
            &segment(client, 101, header.seq.wrapping_add(1), tcp::ACK, &[]),
            now,
            facts(32)
        ),
        Rx::Dropped(DropReason::NotForUs)
    ));
    assert!(matches!(
        receive(
            &scope,
            &segment(client, 101, header.seq.wrapping_add(1), tcp::ACK, &[]),
            now,
            source
        ),
        Rx::Consumed
    ));
    held.release();
    drop(flow);
    assert_eq!(
        scope.hold_host_source(&facts(34)).err().unwrap().kind(),
        io::ErrorKind::OutOfMemory
    );

    scope.drive(now);
    let fin = output(&scope);
    let (header, _) = decode(&fin);
    assert_ne!(header.flags & tcp::FIN, 0);
    assert_eq!(fin.host_return(), Some(source));
    assert!(matches!(
        receive(
            &scope,
            &segment(
                client,
                101,
                header.seq.wrapping_add(1),
                tcp::ACK | tcp::FIN,
                &[]
            ),
            now,
            source
        ),
        Rx::Consumed
    ));
    fin.release();
    scope.drive(now);
    let final_ack = output(&scope);
    assert_eq!(final_ack.host_return(), Some(source));
    assert_eq!(decode(&final_ack).0.flags, tcp::ACK);
    final_ack.release();
    assert_eq!(
        scope.hold_host_source(&facts(34)).err().unwrap().kind(),
        io::ErrorKind::OutOfMemory
    );
    scope.drive(now + Duration::from_secs(61));
    let expired = scope.hold_host_source(&facts(34)).unwrap();
    drop((expired, second, third));
    scope.shutdown(true);
}

#[test]
fn tun_host_tcp_metadata_preserves_partial_checksum_and_gso_for_both_families() {
    for client in ["192.0.2.1:40000", "[2001:db8::1]:40000"] {
        let client: SocketAddr = client.parse().unwrap();
        let now = Instant::now();
        let (scope, _owner, _) = runtime(now);
        scope.prepare_host().unwrap();
        let mut source = facts(31);
        source.stage = honk_ebpf_common::host::HOST_STAGE_TUN_EGRESS;
        source.family = if client.is_ipv6() {
            libc::AF_INET6
        } else {
            libc::AF_INET
        } as u16;
        let ingress = ingress(source);
        assert_eq!(
            receive(&scope, &segment(client, 100, 0, tcp::SYN, &[]), now, source),
            Rx::Consumed
        );
        let (_, mut flow) = scope.poll_accept().unwrap();
        scope.drive(now);
        let synack = output(&scope);
        let server = decode(&synack).0.seq.wrapping_add(1);
        assert_eq!(synack.host_return(), Some(source));
        drop(synack);
        assert_eq!(
            receive(
                &scope,
                &segment(client, 101, server, tcp::ACK, &[]),
                now,
                source
            ),
            Rx::Consumed
        );
        flow.mark_rx_admitted();
        let payload = b"three-gso-segments-here!!";
        let mut packet = segment(client, 101, server, tcp::ACK, payload);
        let start = wire::parse_ip(&packet).unwrap().payload.start;
        packet[start + 16] ^= 1;
        let (rx, _, _) = scope
            .receive_host_with_source(
                (&packet, RxMeta::VERIFY),
                now,
                &ingress,
                &mut None,
                false,
                |_, _, _, _| panic!("VERIFY accepted corrupt checksum"),
            )
            .unwrap();
        assert_eq!(rx, Rx::Dropped(DropReason::Checksum));
        let meta = RxMeta {
            csum: honk_netstack::Csum::Partial {
                start: start as u16,
                offset: 16,
            },
            gso: Some(honk_netstack::GsoRx {
                kind: honk_netstack::GsoKind::Tcp,
                size: 8,
            }),
        };
        let (rx, report, work) = scope
            .receive_host_with_source(
                (&packet, meta),
                now,
                &ingress,
                &mut None,
                false,
                |_, _, captured, _| {
                    assert_eq!(*captured, source);
                    true
                },
            )
            .unwrap();
        assert_eq!(rx, Rx::Consumed);
        assert!(report.qualified_rx);
        assert!(work.is_none(), "TCP keeps its source on the original flow");
        assert_eq!(flow.packet_source().unwrap().facts(), source);
        let mut bytes = [0; 64];
        let mut read = tokio::io::ReadBuf::new(&mut bytes);
        assert!(matches!(
            std::pin::Pin::new(&mut flow).poll_read(&mut context(), &mut read),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read.filled(), payload);
    }
}
