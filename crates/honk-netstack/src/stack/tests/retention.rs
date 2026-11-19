use super::*;
use std::time::Duration;

fn pair(now: Instant, contextual: bool) -> (Stack, Stack, FlowId, FlowId) {
    let mut cfg = Config::new([4; 32]);
    cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
    if contextual {
        cfg.shared_budget = Some(crate::MemoryBudget::new(cfg.memory_limit));
    }
    let mut client = Stack::new(cfg, now);
    if contextual {
        client.prepare_source_context().unwrap();
    }
    let mut cfg = Config::new([5; 32]);
    cfg.mode = Mode::Transparent {
        exclude: crate::ExcludeSet::default(),
    };
    let mut server = Stack::new(cfg, now);
    let id = client
        .tcp_connect(now, "198.51.100.1:443".parse().unwrap())
        .unwrap();
    let mut packet = [0; 2000];
    let n = client.poll_transmit(now, &mut packet).unwrap();
    assert_eq!(server.receive(now, &packet[..n]), Rx::Consumed);
    let accepted = server.poll_accept().unwrap().id;
    server
        .tcp_accept(accepted, crate::AcceptOpts::default())
        .unwrap();
    let n = server.poll_transmit(now, &mut packet).unwrap();
    assert_eq!(client.receive(now, &packet[..n]), Rx::Consumed);
    let n = client.poll_transmit(now, &mut packet).unwrap();
    assert_eq!(server.receive(now, &packet[..n]), Rx::Consumed);
    assert_eq!(client.tcp_state(id), Some(TcpState::Established));
    assert_eq!(server.tcp_state(accepted), Some(TcpState::Established));
    (client, server, id, accepted)
}

fn retained_time_wait(now: Instant, source: Option<SourceContext>) -> (Stack, FlowId, Vec<u8>) {
    let (mut client, mut server, id, accepted) = pair(now, source.is_some());
    if let Some(source) = source {
        client.table.set_source(id.idx, Some(source));
    }
    client.tcp_shutdown(id).unwrap();
    let mut packet = [0; 2000];
    let n = client.poll_transmit(now, &mut packet).unwrap();
    assert_eq!(server.receive(now, &packet[..n]), Rx::Consumed);
    assert_eq!(server.tcp_read(accepted, &mut [0; 1]), Ok(0));
    server.tcp_close(accepted);
    let mut fin = None;
    for _ in 0..8 {
        while let Some(n) = server.poll_transmit(now, &mut packet) {
            let ip = wire::parse_ip(&packet[..n]).unwrap();
            let (h, _) = wire::tcp::parse(&packet[ip.payload]).unwrap();
            if h.flags & wire::tcp::FIN != 0 {
                fin = Some(packet[..n].to_vec());
            }
            let rx = match source {
                Some(source) => {
                    client
                        .receive_with_context(now, &packet[..n], RxMeta::VERIFY, source, |_, _| {
                            true
                        })
                        .0
                }
                None => client.receive(now, &packet[..n]),
            };
            assert_eq!(rx, Rx::Consumed);
        }
        while let Some(n) = client.poll_transmit(now, &mut packet) {
            server.receive(now, &packet[..n]);
        }
    }
    assert_eq!(client.tcp_state(id), Some(TcpState::TimeWait));
    while client.poll_event().is_some() {}
    (client, id, fin.unwrap())
}

#[test]
fn exhausted_application_slot_cannot_alias_an_old_handle() {
    let mut table = Table::new();
    let first = table.insert(Flow::Udp { port: 1 });
    table.slots[first.idx as usize].generation = u32::MAX;
    let last = FlowId {
        generation: u32::MAX,
        ..first
    };
    table.remove(last.idx);
    assert_eq!(table.slots[last.idx as usize].generation, 0);
    let next = table.insert(Flow::Udp { port: 1 });
    assert_ne!(next.idx, first.idx);
    assert!(table.get(first).is_none());
    assert!(table.get(last).is_none());
    #[cfg(feature = "fuzz-checks")]
    table.check();
}

#[test]
fn exhaustion_at_compaction_or_expiry_keeps_time_wait_delivery() {
    for generation in [u32::MAX - 1, u32::MAX] {
        let now = Instant::now();
        let (mut stack, original, fin) = retained_time_wait(now, None);
        stack.table.slots[original.idx as usize].generation = generation;
        let id = FlowId {
            generation,
            ..original
        };
        stack.tcp_close(id);
        assert!(stack.tcp_retained(id));
        assert!(!stack.tcp_retained(original));
        assert!(!stack.take_tcp_retention_change());
        assert_eq!(stack.stats().timewait_entries, 1);
        let late = now + Duration::from_secs(30);
        assert_eq!(stack.receive(late, &fin), Rx::Consumed);
        let mut packet = [0; 2000];
        let tx = stack
            .poll_transmit_with(late, &mut packet, TxCaps::NONE)
            .unwrap();
        assert_eq!(tx.flow, Some(id));
        let ip = wire::parse_ip(&packet[..tx.len]).unwrap();
        let (h, _) = wire::tcp::parse(&packet[ip.payload]).unwrap();
        assert_eq!(h.flags, wire::tcp::ACK);
        stack.handle_timeout(now + Duration::from_secs(60));
        assert!(stack.tcp_retained(id));
        assert!(!stack.take_tcp_retention_change());
        stack.handle_timeout(late + Duration::from_secs(60));
        assert!(!stack.tcp_retained(id));
        assert!(stack.take_tcp_retention_change());
        assert_eq!(stack.table.slots[id.idx as usize].generation, 0);
        let new = stack
            .tcp_connect(
                late + Duration::from_secs(61),
                "198.51.100.1:443".parse().unwrap(),
            )
            .unwrap();
        assert_ne!(new.idx, id.idx);
        #[cfg(feature = "fuzz-checks")]
        stack.check();
    }
}

#[test]
fn active_reopen_retires_the_old_protocol_but_never_reuses_an_exhausted_slot() {
    for exhausted in [false, true] {
        let now = Instant::now();
        let (mut stack, original, _) = retained_time_wait(now, None);
        let id = if exhausted {
            stack.table.slots[original.idx as usize].generation = u32::MAX;
            FlowId {
                generation: u32::MAX,
                ..original
            }
        } else {
            original
        };
        stack.tcp_close(id);
        assert!(stack.tcp_retained(id));
        assert!(!stack.take_tcp_retention_change());
        stack.ports = Ports::new(&stack.cfg.secret);
        let later = now + Duration::from_secs(1);
        let new = stack
            .tcp_connect(later, "198.51.100.1:443".parse().unwrap())
            .unwrap();
        assert_ne!(id, new);
        assert_eq!(new.idx != id.idx, exhausted);
        assert!(!stack.tcp_retained(id));
        assert!(stack.tcp_retained(new));
        assert!(stack.take_tcp_retention_change());
        let mut packet = [0; 2000];
        let tx = stack
            .poll_transmit_with(later, &mut packet, TxCaps::NONE)
            .unwrap();
        assert_eq!(tx.flow, Some(new));
        #[cfg(feature = "fuzz-checks")]
        stack.check();
    }
}

#[test]
fn source_survives_retained_and_exhausted_time_wait_until_a_legal_reopen() {
    let source = SourceContext {
        lineage: std::num::NonZeroU64::new(1).unwrap(),
        snapshot: std::num::NonZeroU64::new(1).unwrap(),
    };
    let newer = SourceContext {
        snapshot: std::num::NonZeroU64::new(2).unwrap(),
        ..source
    };
    let foreign = SourceContext {
        lineage: std::num::NonZeroU64::new(2).unwrap(),
        snapshot: std::num::NonZeroU64::new(3).unwrap(),
    };
    for exhausted in [false, true] {
        let now = Instant::now();
        let (mut stack, original, fin) = retained_time_wait(now, Some(source));
        stack.cfg.mode = Mode::Transparent {
            exclude: crate::ExcludeSet::default(),
        };
        let generation = if exhausted {
            u32::MAX
        } else {
            original.generation
        };
        stack.table.slots[original.idx as usize].generation = generation;
        let id = FlowId {
            generation,
            ..original
        };
        let (rx, _) = stack.receive_with_context(now, &fin, RxMeta::VERIFY, foreign, |_, _| true);
        assert_eq!(rx, Rx::Dropped(DropReason::NotForUs));
        stack.receive_with_context(now, &fin, RxMeta::VERIFY, newer, |_, effective| {
            assert_eq!(effective, source);
            true
        });
        let mut packet = [0; 2000];
        let retained = stack
            .poll_transmit_with(now, &mut packet, TxCaps::NONE)
            .unwrap();
        assert_eq!((retained.flow, retained.source), (Some(id), Some(source)));
        stack.tcp_close(id);
        assert_eq!(stack.stats().timewait_entries, 1);
        let mut contexts = Vec::new();
        stack.visit_retained_source_contexts(|source| contexts.push(source));
        assert_eq!(contexts, [source]);
        let late = now + Duration::from_secs(30);
        assert_eq!(
            stack
                .receive_with_context(late, &fin, RxMeta::VERIFY, foreign, |_, _| true)
                .0,
            Rx::Dropped(DropReason::NotForUs)
        );
        stack.receive_with_context(late, &fin, RxMeta::VERIFY, newer, |_, effective| {
            assert_eq!(effective, source);
            true
        });
        let old_output = stack
            .poll_transmit_with(late, &mut packet, TxCaps::NONE)
            .unwrap();
        assert_eq!(
            (old_output.flow, old_output.source),
            (Some(id), Some(source))
        );
        let Some(Flow::TimeWait(tw)) = &stack.table.slots[id.idx as usize].flow else {
            panic!("missing compact TIME_WAIT")
        };
        let tuple = tw.tuple;
        let sequence = tw.rcv_nxt;
        let timestamp = tw.ts_recent.unwrap();
        let syn = |seq, ts| {
            let mut packet = [0; 128];
            let header = wire::tcp::Header {
                src_port: tuple.remote.port(),
                dst_port: tuple.local.port(),
                seq,
                ack: 0,
                flags: wire::tcp::SYN,
                window: 60_000,
                urgent: 0,
                options: wire::tcp::Options {
                    timestamps: Some((ts, 0)),
                    ..Default::default()
                },
            };
            let len = wire::tcp::emit_packet(
                &mut packet,
                tuple.remote.ip(),
                tuple.local.ip(),
                &header,
                [&[], &[]],
            )
            .unwrap();
            packet[..len].to_vec()
        };
        let stale = syn(sequence.wrapping_sub(1), timestamp);
        assert_eq!(
            stack
                .receive_with_context(late, &stale, RxMeta::VERIFY, foreign, |_, _| true)
                .0,
            Rx::Dropped(DropReason::NotForUs)
        );
        assert!(stack.tcp_retained(id));
        let fresh = syn(sequence.wrapping_add(100_000), timestamp.wrapping_add(1));
        let (rx, report) =
            stack.receive_with_context(late, &fresh, RxMeta::VERIFY, foreign, |_, effective| {
                assert_eq!(effective, foreign);
                true
            });
        assert_eq!(rx, Rx::Consumed);
        let ReceiveOutcome::TcpNew(new) = report.outcome else {
            panic!("legal SYN did not reopen TIME_WAIT")
        };
        assert_ne!(new, id);
        assert!(!stack.tcp_retained(id));
        stack.tcp_accept(new, crate::AcceptOpts::default()).unwrap();
        let tx = stack
            .poll_transmit_with(late, &mut packet, TxCaps::NONE)
            .unwrap();
        assert_eq!((tx.flow, tx.source), (Some(new), Some(foreign)));
        assert_eq!(
            (old_output.flow, old_output.source),
            (Some(id), Some(source))
        );
    }
}
