use super::*;
use honk_netstack::{ExcludeSet, Mode, Transmit, TxCsum};

fn mode(transparent: bool) -> Config {
    let mut cfg = config();
    if transparent {
        cfg.mode = Mode::Transparent {
            exclude: ExcludeSet::default(),
        };
    }
    cfg
}

fn control(stack: &mut Stack, now: Instant) -> Option<(Transmit, Packet)> {
    let mut out = [0; 2048];
    let tx = stack.poll_control_transmit(now, &mut out)?;
    assert_eq!((tx.gso, tx.csum), (None, TxCsum::Full));
    let packet = Packet::decode(out[..tx.len].to_vec());
    assert!(
        packet.data().is_empty(),
        "control credit cannot carry payload"
    );
    Some((tx, packet))
}

#[test]
fn syn_retransmission_and_unknown_flow_reset_need_only_control_credit() {
    for transparent in [false, true] {
        for v6 in [false, true] {
            let now = Instant::now();
            let mut stack = Stack::new(mode(transparent), now);
            let dst = remote(v6);
            let id = stack.tcp_connect(now, dst).unwrap();
            assert!(stack.poll_control_transmit(now, &mut [0; 1]).is_none());
            let (tx, syn) = control(&mut stack, now).expect("initial SYN");
            assert_eq!(tx.flow, Some(id));
            assert_eq!(syn.h.flags, tcp::SYN);
            let due = now + Duration::from_secs(1);
            stack.handle_timeout(due);
            let (tx, retransmit) = control(&mut stack, due).expect("SYN retransmission");
            assert_eq!(tx.flow, Some(id));
            assert_eq!(
                (retransmit.h.seq, retransmit.h.flags),
                (syn.h.seq, tcp::SYN)
            );
            let h = tcp::Header {
                src_port: 12345,
                dst_port: 12346,
                seq: 100,
                ack: 777,
                flags: tcp::ACK,
                window: 0,
                urgent: 0,
                options: tcp::Options::default(),
            };
            let local = SocketAddr::new(syn.ip.src, h.dst_port);
            let remote = SocketAddr::new(dst.ip(), h.src_port);
            assert_eq!(
                stack.receive(due, &encode_tcp(remote, local, &h, &[])),
                Rx::Dropped(DropReason::NoFlow)
            );
            let (tx, reset) = control(&mut stack, due).expect("stateless RST");
            assert_eq!(tx.flow, None);
            assert_eq!((reset.h.seq, reset.h.flags), (777, tcp::RST));
            assert_eq!((reset.ip.src, reset.ip.dst), (local.ip(), remote.ip()));
        }
    }
}

#[test]
fn control_credit_rotates_past_bulk_to_ack_reset_and_fin_then_bulk_resumes() {
    for transparent in [false, true] {
        for v6 in [false, true] {
            let mut now = Instant::now();
            let mut stack = Stack::new(mode(transparent), now);
            let mut peers = Vec::new();
            for port in 443..447 {
                let mut dst = remote(v6);
                dst.set_port(port);
                peers.push(open(&mut stack, &mut now, dst, false, true));
            }
            let data = pattern(2000);
            for p in &peers[..2] {
                assert_eq!(stack.tcp_write(p.id, &data), Ok(data.len()));
            }
            let h = peers[1].header(now, peers[1].start);
            let incoming = b"peer can still progress";
            assert_eq!(
                stack.receive(now, &peers[1].packet(&h, incoming)),
                Rx::Consumed
            );
            peers[1].next += incoming.len() as u32;
            stack.tcp_shutdown(peers[2].id).unwrap();
            stack.tcp_abort(peers[3].id);
            assert!(stack.poll_control_transmit(now, &mut [0; 1]).is_none());

            let mut seen = [false; 3];
            for _ in 0..3 {
                let (tx, p) = control(&mut stack, now).expect("control behind bulk is reachable");
                let i = peers
                    .iter()
                    .position(|peer| Some(peer.id) == tx.flow)
                    .unwrap();
                assert_eq!(
                    (p.ip.src, p.ip.dst),
                    (peers[i].local.ip(), peers[i].remote.ip())
                );
                assert_eq!(
                    (p.h.src_port, p.h.dst_port),
                    (peers[i].local.port(), peers[i].remote.port())
                );
                assert_eq!(p.h.seq, peers[i].start);
                assert_eq!(p.h.ack, peers[i].next);
                match i {
                    1 => assert_eq!(p.h.flags, tcp::ACK),
                    2 => assert_eq!(p.h.flags, tcp::ACK | tcp::FIN),
                    3 => assert_eq!(p.h.flags, tcp::ACK | tcp::RST),
                    _ => panic!("bulk-only flow consumed control credit"),
                }
                assert!(!seen[i - 1]);
                seen[i - 1] = true;
            }
            assert_eq!(seen, [true; 3]);
            for _ in 0..8 {
                assert!(
                    control(&mut stack, now).is_none(),
                    "bounded all-bulk scan terminates"
                );
            }
            assert_eq!(stack.tcp_state(peers[2].id), Some(TcpState::FinWait1));
            for p in &peers[..2] {
                let stats = stack.tcp_stats(p.id).unwrap();
                assert_eq!(
                    (
                        stats.outstanding_bytes,
                        stats.tlp_probes,
                        stats.retrans_segments
                    ),
                    (0, 0, 0)
                );
            }
            let mut received = [Vec::new(), Vec::new()];
            let packets = drain_paced(&mut stack, &mut now);
            for p in packets {
                let i = peers[..2]
                    .iter()
                    .position(|peer| peer.local.port() == p.h.src_port)
                    .unwrap();
                assert_eq!(
                    p.h.seq,
                    peers[i].start.wrapping_add(received[i].len() as u32)
                );
                received[i].extend_from_slice(p.data());
            }
            assert_eq!(received, [data.clone(), data]);
            let mut read = [0; 64];
            let n = stack.tcp_read(peers[1].id, &mut read).unwrap();
            assert_eq!(&read[..n], incoming);
        }
    }
}

#[test]
fn control_credit_preserves_due_tlp_for_retransmitted_or_new_payload() {
    for transparent in [false, true] {
        for new_payload in [false, true] {
            let mut now = Instant::now();
            let mut stack = Stack::new(mode(transparent), now);
            let mut peer = open(&mut stack, &mut now, remote(false), false, true);
            assert_eq!(stack.tcp_write(peer.id, &pattern(2000)), Ok(2000));
            let sent = drain_paced(&mut stack, &mut now);
            assert_eq!(sent.len(), 2);
            if new_payload {
                assert_eq!(stack.tcp_write(peer.id, b"new tail"), Ok(8));
            }
            now += Duration::from_millis(20);
            stack.handle_timeout(now);
            let before = stack.tcp_stats(peer.id).unwrap();
            assert_eq!((before.tlp_probes, before.rto_count), (0, 0));
            let h = peer.header(now, peer.start);
            assert_eq!(stack.receive(now, &peer.packet(&h, b"peer")), Rx::Consumed);
            peer.next = peer.next.wrapping_add(4);
            assert!(stack.poll_control_transmit(now, &mut [0; 1]).is_none());
            let (tx, ack) =
                control(&mut stack, now).expect("ACK still progresses while a payload TLP waits");
            assert_eq!(tx.flow, Some(peer.id));
            assert_eq!(
                (ack.h.flags, ack.h.seq, ack.h.ack),
                (tcp::ACK, peer.start.wrapping_add(2000), peer.next)
            );
            let deadline = stack.poll_timeout();
            for _ in 0..8 {
                assert!(control(&mut stack, now).is_none());
                assert!(stack.poll_control_transmit(now, &mut [0; 1]).is_none());
            }
            let held = stack.tcp_stats(peer.id).unwrap();
            assert_eq!(
                (
                    held.outstanding_bytes,
                    held.tlp_probes,
                    held.retrans_segments
                ),
                (
                    before.outstanding_bytes,
                    before.tlp_probes,
                    before.retrans_segments
                )
            );
            assert_eq!(stack.poll_timeout(), deadline);
            let probe =
                pull(&mut stack, now).expect("returning bulk credit sends the still-due TLP");
            if new_payload {
                assert_eq!(
                    (probe.h.seq, probe.data()),
                    (peer.start.wrapping_add(2000), b"new tail".as_slice())
                );
            } else {
                assert_eq!((probe.h.seq, probe.data()), (sent[1].h.seq, sent[1].data()));
            }
            assert_eq!(stack.tcp_stats(peer.id).unwrap().tlp_probes, 1);
            peer.ack(
                &mut stack,
                now + Duration::from_millis(10),
                peer.start
                    .wrapping_add(2000 + if new_payload { 8 } else { 0 }),
            );
            assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 0);
        }
    }
}

#[test]
fn control_credit_preserves_lost_payload_and_cannot_send_fin_ahead_of_it() {
    for transparent in [false, true] {
        let mut now = Instant::now();
        let mut stack = Stack::new(mode(transparent), now);
        let peer = open(&mut stack, &mut now, remote(false), false, false);
        assert_eq!(stack.tcp_write(peer.id, b"before FIN"), Ok(10));
        stack.tcp_shutdown(peer.id).unwrap();
        assert!(control(&mut stack, now).is_none());
        let packet = pull(&mut stack, now).expect("bulk and ordered FIN");
        assert_eq!(
            (packet.h.seq, packet.data()),
            (peer.start, b"before FIN".as_slice())
        );
        assert_ne!(packet.h.flags & tcp::FIN, 0);
        now += stack.tcp_stats(peer.id).unwrap().rto;
        stack.handle_timeout(now);
        let before = stack.tcp_stats(peer.id).unwrap();
        assert_eq!(before.rto_count, 1);
        for _ in 0..4 {
            assert!(control(&mut stack, now).is_none());
        }
        let held = stack.tcp_stats(peer.id).unwrap();
        assert_eq!(
            (
                held.outstanding_bytes,
                held.lost_bytes,
                held.retrans_segments
            ),
            (
                before.outstanding_bytes,
                before.lost_bytes,
                before.retrans_segments
            )
        );
        let retransmit = pull(&mut stack, now).expect("lost bulk survives control-only pulls");
        assert_eq!(
            (retransmit.h.seq, retransmit.h.flags, retransmit.data()),
            (packet.h.seq, packet.h.flags, packet.data())
        );
    }
}

#[test]
fn persist_and_payload_free_fin_retransmission_use_control_credit() {
    for transparent in [false, true] {
        for v6 in [false, true] {
            let mut now = Instant::now();
            let mut stack = Stack::new(mode(transparent), now);
            let mut peer = open(&mut stack, &mut now, remote(v6), true, true);
            peer.window = 0;
            peer.ack(&mut stack, now, peer.start);
            assert_eq!(stack.tcp_write(peer.id, b"held"), Ok(4));
            assert!(control(&mut stack, now).is_none());
            now += Duration::from_millis(200);
            stack.handle_timeout(now);
            assert!(stack.poll_control_transmit(now, &mut [0; 1]).is_none());
            let (tx, probe) = control(&mut stack, now).expect("persist probe");
            assert_eq!(tx.flow, Some(peer.id));
            assert_eq!(
                (probe.h.seq, probe.h.ack, probe.h.flags),
                (peer.start.wrapping_sub(1), peer.next, tcp::ACK)
            );
            assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 0);
            assert!(control(&mut stack, now).is_none());
            peer.window = 60_000;
            peer.ack(&mut stack, now, peer.start);
            assert!(control(&mut stack, now).is_none());
            let data = pull(&mut stack, now).unwrap();
            assert_eq!((data.h.seq, data.data()), (peer.start, b"held".as_slice()));
            now += Duration::from_millis(10);
            peer.ack(&mut stack, now, data.end());
            stack.tcp_shutdown(peer.id).unwrap();
            let (_, fin) = control(&mut stack, now).expect("payload-free FIN");
            assert_eq!((fin.h.seq, fin.h.flags), (data.end(), tcp::ACK | tcp::FIN));
            now += stack.tcp_stats(peer.id).unwrap().rto;
            stack.handle_timeout(now);
            let (_, retransmit) =
                control(&mut stack, now).expect("payload-free FIN retransmission");
            assert_eq!(
                (retransmit.h.seq, retransmit.h.flags),
                (fin.h.seq, fin.h.flags)
            );
            peer.ack(&mut stack, now, fin.end());
            assert_eq!(stack.tcp_state(peer.id), Some(TcpState::FinWait2));
        }
    }
}

#[test]
fn mixed_ack_and_reset_control_pulls_cannot_starve_ordinary_payload() {
    for transparent in [false, true] {
        let mut now = Instant::now();
        let mut stack = Stack::new(mode(transparent), now);
        let mut peers = Vec::new();
        for port in 443..446 {
            let mut destination = remote(false);
            destination.set_port(port);
            peers.push(open(&mut stack, &mut now, destination, false, true));
        }
        let unknown = tcp::Header {
            src_port: 30000,
            dst_port: 30001,
            seq: 1,
            ack: 2,
            flags: tcp::ACK,
            window: 1,
            urgent: 0,
            options: tcp::Options::default(),
        };
        let reset_input = encode_tcp(
            SocketAddr::new(peers[0].remote.ip(), unknown.src_port),
            SocketAddr::new(peers[0].local.ip(), unknown.dst_port),
            &unknown,
            &[],
        );
        let mut out = [0; 2048];
        stack.receive(now, &reset_input);
        control(&mut stack, now).expect("control cursor prime");
        stack.receive(now, &reset_input);
        stack
            .poll_transmit(now, &mut out)
            .expect("ordinary cursor prime");
        assert_eq!(stack.tcp_write(peers[0].id, b"bulk"), Ok(4));
        let mut payload = Vec::new();
        for _ in 0..8 {
            for peer in &mut peers[1..] {
                let header = peer.header(now, peer.start);
                assert_eq!(
                    stack.receive(now, &peer.packet(&header, b"x")),
                    Rx::Consumed
                );
                peer.next += 1;
            }
            stack.receive(now, &reset_input);
            control(&mut stack, now).expect("control remains offered");
            if let Some(length) = stack.poll_transmit(now, &mut out) {
                payload.extend_from_slice(Packet::decode(out[..length].to_vec()).data());
            }
        }
        assert_eq!(payload, b"bulk");
    }
}
