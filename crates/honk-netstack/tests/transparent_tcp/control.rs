use super::*;
use honk_netstack::wire;
use honk_netstack::{Transmit, TxCaps, TxCsum};

fn control(stack: &mut Stack, now: Instant) -> Option<(Transmit, Out)> {
    let mut out = [0; 2000];
    let tx = stack.poll_control_transmit(now, &mut out)?;
    assert_eq!((tx.gso, tx.csum), (None, TxCsum::Full));
    let packet = decode(&out[..tx.len]);
    assert!(packet.payload.is_empty());
    Some((tx, packet))
}

fn queue_bulk(stack: &mut Stack, now: Instant) -> (FlowId, u32) {
    let mut peer = Peer::new("10.0.0.3:40001", DST, 9000);
    assert_eq!(peer.syn(stack, now, 1460), Rx::Consumed);
    let info = info_of(stack);
    stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
    let (tx, synack) = control(stack, now).expect("SYN-ACK needs no bulk credit");
    assert_eq!(tx.flow, Some(info.id));
    assert_eq!(
        (synack.src, synack.dst, synack.h.flags),
        (peer.dst, peer.client, SYN | ACK)
    );
    let start = synack.h.seq.wrapping_add(1);
    peer.seq += 1;
    assert_eq!(
        peer.seg(
            stack,
            now,
            start,
            ACK,
            synack.h.options.timestamps.unwrap().0,
            &[]
        ),
        Rx::Consumed
    );
    assert_eq!(stack.tcp_write(info.id, b"bulk remains queued"), Ok(19));
    (info.id, start)
}

#[test]
fn keepalive_uses_control_credit_while_another_flow_waits_for_bulk() {
    let ka = Keepalive {
        idle: Duration::from_secs(10),
        interval: Duration::from_secs(2),
        probes: 3,
    };
    let mut c = established(
        transparent(),
        AcceptOpts {
            keepalive: Some(ka),
            ..AcceptOpts::default()
        },
    );
    let (bulk, start) = queue_bulk(&mut c.stack, c.t0 + ms(10));
    let now = c.t0 + ms(10_005);
    c.stack.handle_timeout(now);
    assert!(c.stack.poll_control_transmit(now, &mut [0; 1]).is_none());
    let (tx, probe) =
        control(&mut c.stack, now).expect("idle peer is probed despite bulk exhaustion");
    assert_eq!(tx.flow, Some(c.id));
    assert_eq!(
        (probe.h.flags, probe.h.seq, probe.h.ack),
        (ACK, c.snd.wrapping_sub(1), c.peer.seq)
    );
    assert_eq!((probe.src, probe.dst), (c.peer.dst, c.peer.client));
    assert!(control(&mut c.stack, now).is_none());
    assert_eq!(c.stack.tcp_stats(bulk).unwrap().outstanding_bytes, 0);
    c.client_seg(now, ACK, &[]);
    c.stack.handle_timeout(now + ka.interval);
    assert!(control(&mut c.stack, now + ka.interval).is_none());
    assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::Established));
    let out = drain(&mut c.stack, now + ka.interval);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].h.seq, out[0].payload.as_slice()),
        (start, b"bulk remains queued".as_slice())
    );
}

#[test]
fn compact_time_wait_ack_progresses_without_bulk_and_keeps_its_owner() {
    let mut c = established(transparent(), AcceptOpts::default());
    c.stack.tcp_close(c.id);
    let (_, fin) = control(&mut c.stack, c.t0 + ms(10)).expect("FIN uses control credit");
    assert_eq!(fin.h.flags, ACK | FIN);
    let end = fin.h.seq.wrapping_add(1);
    let stamp = fin.h.options.timestamps.unwrap().0;
    c.peer
        .seg(&mut c.stack, c.t0 + ms(20), end, ACK, stamp, &[]);
    c.peer
        .seg(&mut c.stack, c.t0 + ms(30), end, ACK | FIN, stamp, &[]);
    assert!(
        c.stack
            .poll_control_transmit(c.t0 + ms(30), &mut [0; 1])
            .is_none()
    );
    let (tx, ack) = control(&mut c.stack, c.t0 + ms(30)).unwrap();
    assert_eq!(tx.flow, Some(c.id));
    assert_eq!((ack.h.flags, ack.h.seq, ack.h.ack), (ACK, end, c.peer.seq));
    assert_eq!(
        (c.stack.stats().flows, c.stack.stats().timewait_entries),
        (0, 1)
    );
    let (bulk, start) = queue_bulk(&mut c.stack, c.t0 + ms(40));
    let duplicate = build(
        c.peer.client,
        c.peer.dst,
        c.peer.seq.wrapping_sub(1),
        end,
        ACK | FIN,
        Options {
            timestamps: Some((c.peer.ts + 1, stamp)),
            ..Options::default()
        },
        &[],
    );
    let now = c.t0 + ms(50);
    assert_eq!(c.stack.receive(now, &duplicate), Rx::Consumed);
    assert!(c.stack.poll_control_transmit(now, &mut [0; 1]).is_none());
    let (tx, ack) = control(&mut c.stack, now).expect("compact TIME_WAIT ACK bypasses bulk");
    assert_eq!(tx.flow, Some(c.id));
    assert_eq!((ack.h.seq, ack.h.ack, ack.h.flags), (end, c.peer.seq, ACK));
    assert_eq!((ack.src, ack.dst), (c.peer.dst, c.peer.client));
    assert!(c.stack.tcp_retained(c.id));
    assert_eq!(c.stack.tcp_stats(bulk).unwrap().outstanding_bytes, 0);
    assert!(control(&mut c.stack, now).is_none());
    let out = drain(&mut c.stack, now);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].h.seq, out[0].payload.as_slice()),
        (start, b"bulk remains queued".as_slice())
    );
}

#[test]
fn refusal_control_survives_tiny_buffer_and_bulk_readiness() {
    for how in [
        Refuse::Rst,
        Refuse::IcmpUnreachable,
        Refuse::IcmpAdminProhibited,
    ] {
        let now = Instant::now();
        let mut stack = Stack::new(transparent(), now);
        let (bulk, _) = queue_bulk(&mut stack, now);
        let peer = Peer::new(CLIENT, DST, 1000);
        peer.syn(&mut stack, now, 1460);
        let info = info_of(&mut stack);
        stack.tcp_refuse(info.id, how);
        assert!(stack.poll_control_transmit(now, &mut [0; 1]).is_none());
        let mut out = [0; 2000];
        let tx = stack
            .poll_control_transmit(now, &mut out)
            .expect("refusal control");
        assert_eq!(tx.flow, Some(info.id));
        let ip = wire::parse_ip(&out[..tx.len]).unwrap();
        assert_eq!((ip.src, ip.dst), (peer.dst.ip(), peer.client.ip()));
        if how == Refuse::Rst {
            let packet = decode(&out[..tx.len]);
            assert_eq!((packet.h.flags, packet.h.ack), (RST | ACK, 1001));
            assert!(packet.payload.is_empty());
        } else {
            assert_eq!(ip.proto, wire::PROTO_ICMP);
            let msg = &out[ip.payload];
            assert!(wire::icmp::parse(ip.src, ip.dst, msg).unwrap().is_some());
            assert_eq!(
                (msg[0], msg[1]),
                (
                    3,
                    if how == Refuse::IcmpUnreachable {
                        1
                    } else {
                        13
                    }
                )
            );
        }
        assert!(!stack.tcp_retained(info.id));
        assert_eq!(stack.tcp_stats(bulk).unwrap().outstanding_bytes, 0);
        assert!(stack.poll_control_transmit(now, &mut out).is_none());
        assert!(
            stack
                .poll_transmit_with(now, &mut out, TxCaps::NONE)
                .is_some()
        );
    }
}

#[test]
fn reassembly_timeout_icmp_bypasses_udp_fragments_and_fragments_resume_intact() {
    for (src, dst) in [(CLIENT, DST), ("[fd00::2]:40000", "[2001:db8::9]:443")] {
        let now = Instant::now();
        let (src, dst) = (addr(src), addr(dst));
        let payload: Vec<u8> = (0..4000).map(|i| (i % 251) as u8).collect();
        let mut sender = Stack::new(transparent(), now);
        let mut first = [0; 2000];
        let n = sender
            .udp_send_from(src, dst, &payload, &mut first)
            .unwrap();
        let first = &first[..n];
        let quote_len = if src.is_ipv6() { 56 } else { 28 };
        let mut cfg = transparent();
        cfg.fragment_limits.timeout = ms(10);
        let mut stack = Stack::new(cfg, now);
        assert_eq!(stack.receive(now, first), Rx::Consumed);
        let mut out = [0; 2000];
        let n = stack.udp_send_from(dst, src, &payload, &mut out).unwrap();
        let (offset, initial) = fragment_payload(&out[..n]);
        let mut datagram = initial.to_vec();
        assert_eq!(offset, 0);
        let due = now + ms(10);
        stack.handle_timeout(due);
        assert!(stack.poll_control_transmit(due, &mut [0; 1]).is_none());
        let tx = stack
            .poll_control_transmit(due, &mut out)
            .expect("reassembly Time Exceeded");
        assert_eq!((tx.flow, tx.gso, tx.csum), (None, None, TxCsum::Full));
        let ip = wire::parse_ip(&out[..tx.len]).unwrap();
        assert_eq!((ip.src, ip.dst), (dst.ip(), src.ip()));
        assert_eq!(
            ip.proto,
            if src.is_ipv6() {
                wire::PROTO_ICMPV6
            } else {
                wire::PROTO_ICMP
            }
        );
        let msg = &out[ip.payload];
        assert!(wire::icmp::parse(ip.src, ip.dst, msg).is_ok());
        assert_eq!((msg[0], msg[1]), (if src.is_ipv6() { 3 } else { 11 }, 1));
        assert_eq!(&msg[8..], &first[..quote_len]);
        assert!(
            stack.poll_control_transmit(due, &mut out).is_none(),
            "UDP fragments need bulk credit"
        );
        while let Some(n) = stack.poll_transmit(due, &mut out) {
            let (offset, data) = fragment_payload(&out[..n]);
            assert_eq!(offset, datagram.len());
            datagram.extend_from_slice(data);
        }
        assert!(wire::udp::verify_checksum(dst.ip(), src.ip(), &datagram));
        assert_eq!(&datagram[8..], payload);
    }
}

fn fragment_payload(packet: &[u8]) -> (usize, &[u8]) {
    if packet[0] >> 4 == 4 {
        let header = usize::from(packet[0] & 15) * 4;
        assert_eq!(wire::checksum::checksum(&packet[..header]), 0);
        let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        let offset = usize::from(u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff) * 8;
        (offset, &packet[header..length])
    } else {
        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(packet[6], 44);
        let length = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
        let offset = usize::from(u16::from_be_bytes([packet[42], packet[43]]) & 0xfff8);
        (offset, &packet[48..length])
    }
}
