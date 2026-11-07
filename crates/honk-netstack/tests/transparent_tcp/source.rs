use super::*;
use honk_netstack::{ValidatedSource, wire};

fn fragmented(packet: &[u8], id: u32) -> Vec<Vec<u8>> {
    let ip = wire::parse_ip(packet).unwrap();
    let payload = &packet[ip.payload.clone()];
    payload
        .chunks(16)
        .enumerate()
        .map(|(index, data)| {
            let offset = index * 16;
            let more = offset + data.len() < payload.len();
            if ip.src.is_ipv4() {
                let mut fragment = packet[..20].to_vec();
                fragment.extend_from_slice(data);
                fragment[2..4].copy_from_slice(&((20 + data.len()) as u16).to_be_bytes());
                fragment[4..6].copy_from_slice(&(id as u16).to_be_bytes());
                let field = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
                fragment[6..8].copy_from_slice(&field.to_be_bytes());
                fragment[10..12].fill(0);
                let checksum = wire::checksum::checksum(&fragment[..20]);
                fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
                fragment
            } else {
                let mut fragment = packet[..40].to_vec();
                fragment[4..6].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
                fragment[6] = 44;
                fragment.extend_from_slice(&[ip.proto, 0]);
                fragment.extend_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
                fragment.extend_from_slice(&id.to_be_bytes());
                fragment.extend_from_slice(data);
                fragment
            }
        })
        .collect()
}

fn packet(source: SocketAddr, destination: SocketAddr, protocol: u8) -> Vec<u8> {
    if protocol == wire::PROTO_TCP {
        build(source, destination, 100, 0, SYN, Options::default(), &[])
    } else {
        let mut packet = vec![0; 128];
        let length = wire::udp::emit_packet(&mut packet, source, destination, &[0x5a; 48]).unwrap();
        packet.truncate(length);
        packet
    }
}

#[test]
fn fragmented_current_source_never_comes_from_an_older_pending_syn() {
    for (old, current, destination) in [
        ("10.0.0.1:40000", "10.0.0.2:40001", "203.0.113.9:443"),
        ("[fd00::1]:40000", "[fd00::2]:40001", "[2001:db8::9]:443"),
    ] {
        let (old, current, destination) = (addr(old), addr(current), addr(destination));
        for protocol in [wire::PROTO_TCP, wire::PROTO_UDP] {
            let now = Instant::now();
            let mut stack = Stack::new(transparent(), now);
            assert_eq!(
                stack.receive(now, &packet(old, destination, wire::PROTO_TCP)),
                Rx::Consumed
            );
            let expected = ValidatedSource {
                src: current,
                dst: destination,
                protocol,
                tcp_flags: (protocol == wire::PROTO_TCP).then_some(SYN),
            };
            let input = packet(current, destination, protocol);
            let fragments = fragmented(&input, 17);
            let mut reported = Vec::new();
            let mut new_id = None;
            for (index, fragment) in fragments.iter().enumerate() {
                let (rx, report) = stack.receive_with_tcp_admission(now, fragment, |source| {
                    reported.push(source);
                    true
                });
                let source = report.source;
                if index + 1 == fragments.len() {
                    assert_eq!(source, Some(expected));
                    if protocol == wire::PROTO_UDP {
                        assert!(matches!(rx, Rx::TransparentOwned { .. }));
                        assert_eq!(
                            report.outcome,
                            honk_netstack::ReceiveOutcome::DatagramValidated
                        );
                    } else {
                        assert_eq!(rx, Rx::Consumed);
                        let honk_netstack::ReceiveOutcome::TcpNew(id) = report.outcome else {
                            panic!("completion must retain its own new flow identity")
                        };
                        new_id = Some(id);
                    }
                } else {
                    assert_eq!(source, None);
                    assert_eq!(report.outcome, honk_netstack::ReceiveOutcome::Unqualified);
                    assert_eq!(rx, Rx::Consumed);
                    assert!(reported.is_empty());
                }
            }
            assert_eq!(reported, vec![expected]);
            assert_eq!(
                stack.poll_accept().unwrap().client,
                old,
                "older pending SYN is still independent of receipt"
            );
            if protocol == wire::PROTO_TCP {
                let current_syn = stack.poll_accept().unwrap();
                assert_eq!(current_syn.client, current);
                assert_eq!(Some(current_syn.id), new_id);
            }
            assert!(stack.poll_accept().is_none());

            let mut corrupt = input;
            *corrupt.last_mut().unwrap() ^= 1;
            let fragments = fragmented(&corrupt, 18);
            for (index, fragment) in fragments.iter().enumerate() {
                let (rx, source) = stack.receive_with_source(now, fragment, |_| {
                    panic!("invalid completed transport supplied a receipt")
                });
                assert_eq!(source, None);
                if index + 1 == fragments.len() {
                    assert_eq!(rx, Rx::Dropped(DropReason::Checksum));
                }
            }
            let (rx, source) = stack.receive_with_source(
                now,
                &fragmented(&packet(current, destination, protocol), 19)[0],
                |_| panic!("incomplete fragment supplied a stale receipt"),
            );
            assert_eq!(rx, Rx::Consumed);
            assert_eq!(source, None);
        }
    }
}

#[test]
fn checksum_failure_never_reports_and_callback_refusal_precedes_protocol_admission() {
    let now = Instant::now();
    let source = addr(CLIENT);
    let destination = addr(DST);
    for protocol in [wire::PROTO_TCP, wire::PROTO_UDP] {
        let mut stack = Stack::new(transparent(), now);
        let input = packet(source, destination, protocol);
        let mut corrupt = input.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let (rx, receipt) = stack.receive_with_source(now, &corrupt, |_| {
            panic!("checksum failure reached source callback")
        });
        assert_eq!((rx, receipt), (Rx::Dropped(DropReason::Checksum), None));
        let expected = ValidatedSource {
            src: source,
            dst: destination,
            protocol,
            tcp_flags: (protocol == wire::PROTO_TCP).then_some(SYN),
        };
        let mut callbacks = 0;
        let (rx, receipt) = stack.receive_with_source(now, &input, |receipt| {
            callbacks += 1;
            assert_eq!(receipt, expected);
            false
        });
        assert_eq!(callbacks, 1);
        assert_eq!(
            (rx, receipt),
            (Rx::Dropped(DropReason::NotForUs), Some(expected))
        );
        assert!(stack.poll_accept().is_none());
        assert!(stack.poll_transmit(now, &mut [0; 1500]).is_none());
        let rx = stack.receive(now, &input);
        if protocol == wire::PROTO_TCP {
            assert_eq!(rx, Rx::Consumed);
            assert_eq!(
                stack.poll_accept().unwrap().client,
                source,
                "refused receipt must not leave an absorbing half-open flow"
            );
        } else {
            assert!(matches!(rx, Rx::Transparent { .. }));
        }
    }
}

fn matching_output(reported: &mut Stack, ordinary: &mut Stack, now: Instant) -> Vec<Vec<u8>> {
    let mut outputs = Vec::new();
    let (mut left, mut right) = ([0; 2000], [0; 2000]);
    loop {
        let a = reported.poll_transmit(now, &mut left);
        let b = ordinary.poll_transmit(now, &mut right);
        assert_eq!(a, b, "reporting must preserve output obligations");
        let Some(length) = a else { break };
        assert_eq!(&left[..length], &right[..length]);
        outputs.push(left[..length].to_vec());
    }
    outputs
}

fn report_pair(
    reported: &mut Stack,
    ordinary: &mut Stack,
    now: Instant,
    packet: &[u8],
) -> honk_netstack::ReceiveReport {
    let (rx, report) = reported.receive_with_tcp_admission(now, packet, |_| true);
    assert_eq!(rx, ordinary.receive(now, packet));
    matching_output(reported, ordinary, now);
    report
}

#[test]
fn protocol_outcomes_preserve_ordinary_actions_and_exclude_rejections() {
    use honk_netstack::ReceiveOutcome::{TcpAccepted, TcpNew, Unqualified};
    for (source, destination) in [
        (addr(CLIENT), addr(DST)),
        (addr("[fd00::2]:40000"), addr("[2001:db8::9]:443")),
    ] {
        let now = Instant::now();
        let mut reported = Stack::new(transparent(), now);
        let mut ordinary = Stack::new(transparent(), now);
        let syn = build(source, destination, 100, 0, SYN, opts_syn(1200), &[]);
        let report = report_pair(&mut reported, &mut ordinary, now, &syn);
        let TcpNew(id) = report.outcome else {
            panic!("missing exact new incarnation")
        };
        assert!(report.source.is_some());
        assert_eq!(
            report_pair(&mut reported, &mut ordinary, now, &syn).outcome,
            Unqualified
        );
        assert_eq!(reported.poll_accept().unwrap().id, id);
        assert_eq!(ordinary.poll_accept().unwrap().id, id);
        reported.tcp_accept(id, AcceptOpts::default()).unwrap();
        ordinary.tcp_accept(id, AcceptOpts::default()).unwrap();
        let replies = matching_output(&mut reported, &mut ordinary, now);
        let server = decode(&replies[0]).h.seq.wrapping_add(1);
        let input = |seq, ack, flags, ts, data: &[u8]| {
            build(
                source,
                destination,
                seq,
                ack,
                flags,
                Options {
                    timestamps: Some((ts, 0)),
                    ..Options::default()
                },
                data,
            )
        };
        let invalid_handshake = input(101, server.wrapping_add(1), ACK, 5001, &[]);
        assert_eq!(
            report_pair(&mut reported, &mut ordinary, now, &invalid_handshake).outcome,
            Unqualified
        );
        let ack = input(101, server, ACK, 5001, &[]);
        let mut corrupt = ack.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            report_pair(&mut reported, &mut ordinary, now, &corrupt),
            Default::default()
        );
        assert_eq!(
            report_pair(&mut reported, &mut ordinary, now, &ack).outcome,
            TcpAccepted(id)
        );
        for rejected in [
            input(101, server, ACK, 4999, &[]),
            input(101, server.wrapping_add(1), ACK, 5002, &[]),
            input(100, server, ACK, 5002, &[]),
            input(101, server, SYN | ACK, 5002, &[]),
            input(102, server, RST | ACK, 5002, &[]),
            input(101, 0, 0, 5002, &[]),
        ] {
            let report = report_pair(&mut reported, &mut ordinary, now, &rejected);
            assert!(report.source.is_some());
            assert_eq!(report.outcome, Unqualified);
        }
        for index in 0..33 {
            let data = input(103 + index * 2, server, ACK, 5002, b"x");
            let outcome = report_pair(&mut reported, &mut ordinary, now, &data).outcome;
            assert_eq!(
                outcome,
                if index < 32 {
                    TcpAccepted(id)
                } else {
                    Unqualified
                }
            );
        }
        let data = input(101, server, ACK, 5003, b"a");
        assert_eq!(
            report_pair(&mut reported, &mut ordinary, now, &data).outcome,
            TcpAccepted(id)
        );
        let fin = input(102, server, ACK | FIN, 5004, &[]);
        assert_eq!(
            report_pair(&mut reported, &mut ordinary, now, &fin).outcome,
            TcpAccepted(id)
        );
        let reset = input(103, server, RST, 5004, &[]);
        assert_eq!(
            report_pair(&mut reported, &mut ordinary, now, &reset).outcome,
            TcpAccepted(id)
        );
        assert_eq!(
            report_pair(&mut reported, &mut ordinary, now, &ack).outcome,
            Unqualified
        );
    }
}

#[test]
fn detailed_reports_keep_source_gate_capacity_and_datagram_evidence_separate() {
    use honk_netstack::ReceiveOutcome::{DatagramValidated, Unqualified};
    let now = Instant::now();
    let source = addr(CLIENT);
    let destination = addr(DST);
    for protocol in [wire::PROTO_TCP, wire::PROTO_UDP] {
        let mut cfg = transparent();
        cfg.max_flows = 0;
        let mut stack = Stack::new(cfg, now);
        let packet = packet(source, destination, protocol);
        let (rx, report) = stack.receive_with_tcp_admission(now, &packet, |_| false);
        assert_eq!(rx, Rx::Dropped(DropReason::NotForUs));
        assert!(report.source.is_some());
        assert_eq!(report.outcome, Unqualified);
        let (_, report) = stack.receive_with_tcp_admission(now, &packet, |_| true);
        assert!(report.source.is_some());
        assert_eq!(
            report.outcome,
            if protocol == wire::PROTO_TCP {
                Unqualified
            } else {
                DatagramValidated
            }
        );
    }
}

#[test]
fn active_open_reports_only_valid_handshake_or_exact_reset() {
    use honk_netstack::ReceiveOutcome::{TcpAccepted, Unqualified};
    for reset in [false, true] {
        let now = Instant::now();
        let mut cfg = Config::new([18; 32]);
        cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
        let mut reported = Stack::new(cfg.clone(), now);
        let mut ordinary = Stack::new(cfg, now);
        let remote = addr(DST);
        let id = reported.tcp_connect(now, remote).unwrap();
        assert_eq!(ordinary.tcp_connect(now, remote).unwrap(), id);
        let outgoing = matching_output(&mut reported, &mut ordinary, now);
        let syn = decode(&outgoing[0]);
        let ack = syn.h.seq.wrapping_add(1);
        for (flags, peer_ack) in [(ACK, ack.wrapping_add(1)), (RST, 0), (0, 0)] {
            let packet = build(
                remote,
                syn.src,
                200,
                peer_ack,
                flags,
                Options::default(),
                &[],
            );
            let report = report_pair(&mut reported, &mut ordinary, now, &packet);
            assert!(report.source.is_some());
            assert_eq!(report.outcome, Unqualified);
        }
        let packet = build(
            remote,
            syn.src,
            200,
            ack,
            ACK | if reset { RST } else { SYN },
            Options::default(),
            &[],
        );
        assert_eq!(
            report_pair(&mut reported, &mut ordinary, now, &packet).outcome,
            TcpAccepted(id)
        );
        assert_eq!(reported.tcp_state(id), ordinary.tcp_state(id));
    }
}
