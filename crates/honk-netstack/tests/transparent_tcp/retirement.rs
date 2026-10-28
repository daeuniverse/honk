use super::*;
use honk_netstack::{IcmpLimits, Transmit, TxCaps};

fn pull(stack: &mut Stack, now: Instant) -> Option<(Transmit, Vec<u8>)> {
    let mut packet = vec![0; 2000];
    let tx = stack.poll_transmit_with(now, &mut packet, TxCaps::NONE)?;
    packet.truncate(tx.len);
    Some((tx, packet))
}

fn enter_time_wait(c: &mut Conn) -> (Instant, u32, u32) {
    c.stack.tcp_close(c.id);
    assert!(c.stack.tcp_retained(c.id));
    assert_eq!(c.stack.tcp_state(c.id), None);
    let (tx, packet) = pull(&mut c.stack, c.t0 + ms(10)).unwrap();
    assert_eq!(tx.flow, Some(c.id));
    let fin = decode(&packet).h;
    assert_ne!(fin.flags & FIN, 0);
    let end = fin.seq.wrapping_add(1);
    let stamp = fin.options.timestamps.unwrap().0;
    c.peer
        .seg(&mut c.stack, c.t0 + ms(20), end, ACK, stamp, &[]);
    c.peer
        .seg(&mut c.stack, c.t0 + ms(30), end, ACK | FIN, stamp, &[]);
    let closed = c.t0 + ms(30);
    assert!(c.stack.tcp_retained(c.id));
    assert!(
        c.stack
            .poll_transmit_with(closed, &mut [0; 1], TxCaps::NONE)
            .is_none()
    );
    assert_eq!(c.stack.stats().flows, 1);
    let (tx, packet) = pull(&mut c.stack, closed).unwrap();
    assert_eq!(tx.flow, Some(c.id));
    assert_eq!(decode(&packet).h.ack, c.peer.seq);
    assert_eq!(
        (c.stack.stats().flows, c.stack.stats().timewait_entries),
        (0, 1)
    );
    assert!(c.stack.tcp_retained(c.id));
    (closed, end, stamp)
}

#[test]
fn application_close_and_compaction_do_not_retire_the_protocol_owner() {
    let mut c = established(transparent(), AcceptOpts::default());
    let idle = c.t0 + Duration::from_secs(3600);
    c.stack.handle_timeout(idle);
    assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::Established));
    assert!(c.stack.tcp_retained(c.id));
    c.t0 = idle;
    let (closed, _, _) = enter_time_wait(&mut c);
    c.stack
        .handle_timeout(closed + Duration::from_secs(60) - Duration::from_nanos(1));
    assert!(c.stack.tcp_retained(c.id));
    c.stack.handle_timeout(closed + Duration::from_secs(60));
    assert!(!c.stack.tcp_retained(c.id));
}

#[test]
fn half_close_keeps_the_application_and_final_fin_obligations() {
    let mut c = established(transparent(), AcceptOpts::default());
    c.stack.tcp_shutdown(c.id).unwrap();
    let (tx, packet) = pull(&mut c.stack, c.t0 + ms(10)).unwrap();
    assert_eq!(tx.flow, Some(c.id));
    let fin = decode(&packet).h;
    let end = fin.seq.wrapping_add(1);
    c.peer
        .seg(&mut c.stack, c.t0 + ms(20), end, ACK, c.tsval, &[]);
    assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::FinWait2));
    assert!(c.stack.tcp_retained(c.id));
    c.peer.seg(
        &mut c.stack,
        c.t0 + ms(30),
        end,
        ACK | FIN,
        c.tsval,
        b"tail",
    );
    let (tx, _) = pull(&mut c.stack, c.t0 + ms(30)).unwrap();
    assert_eq!(tx.flow, Some(c.id));
    assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::TimeWait));
    assert!(c.stack.tcp_retained(c.id));
    let mut data = [0; 4];
    assert_eq!(c.stack.tcp_read(c.id, &mut data), Ok(4));
    assert_eq!(&data, b"tail");
    assert!(c.stack.tcp_retained(c.id));
    c.stack.tcp_close(c.id);
    assert_eq!(c.stack.tcp_state(c.id), None);
    assert!(c.stack.tcp_retained(c.id));
    c.stack.handle_timeout(c.t0 + Duration::from_secs(61));
    assert!(!c.stack.tcp_retained(c.id));
}

#[test]
fn pending_time_wait_ack_prevents_retirement_and_keeps_original_attribution() {
    let mut c = established(transparent(), AcceptOpts::default());
    c.client_seg(c.t0 + ms(1), ACK, b"tail");
    assert_eq!(c.stack.tcp_read(c.id, &mut [0; 4]), Ok(4));
    drain(&mut c.stack, c.t0 + ms(1));
    let (closed, end, stamp) = enter_time_wait(&mut c);
    let duplicate = build(
        c.peer.client,
        c.peer.dst,
        c.peer.seq.wrapping_sub(5),
        end,
        ACK | tcp::PSH,
        Options {
            timestamps: Some((c.peer.ts + 1, stamp)),
            ..Options::default()
        },
        b"tail",
    );
    let expiry = closed + Duration::from_secs(60);
    assert_eq!(c.stack.receive(expiry - ms(1), &duplicate), Rx::Consumed);
    c.stack.handle_timeout(expiry);
    assert!(c.stack.tcp_retained(c.id));
    let (tx, packet) = pull(&mut c.stack, expiry).unwrap();
    assert_eq!(tx.flow, Some(c.id));
    let ack = decode(&packet).h;
    assert_eq!((ack.flags, ack.ack), (ACK, c.peer.seq));
    assert_eq!(ack.options.timestamps.unwrap().1, c.peer.ts);
    c.stack.handle_timeout(expiry + Duration::from_secs(60));
    assert!(!c.stack.tcp_retained(c.id));
}

#[test]
fn late_fin_restarts_retention_without_creating_a_new_handle() {
    let mut c = established(transparent(), AcceptOpts::default());
    let (closed, end, stamp) = enter_time_wait(&mut c);
    let late = build(
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
    let resent = closed + Duration::from_secs(30);
    assert_eq!(c.stack.receive(resent, &late), Rx::Consumed);
    let (tx, packet) = pull(&mut c.stack, resent).unwrap();
    assert_eq!(tx.flow, Some(c.id));
    assert_eq!(decode(&packet).h.flags, ACK);
    c.stack.handle_timeout(closed + Duration::from_secs(60));
    assert!(c.stack.tcp_retained(c.id));
    c.stack.handle_timeout(resent + Duration::from_secs(60));
    assert!(!c.stack.tcp_retained(c.id));
}

#[test]
fn refusal_output_retains_its_old_owner_across_slot_and_tuple_reuse() {
    for how in [Refuse::Rst, Refuse::IcmpUnreachable, Refuse::Drop] {
        let now = Instant::now();
        let mut stack = Stack::new(transparent(), now);
        let mut peer = Peer::new(CLIENT, DST, 1000);
        peer.syn(&mut stack, now, 1460);
        let old = info_of(&mut stack).id;
        stack.tcp_refuse(old, how);
        assert_eq!(stack.tcp_state(old), None);
        assert_eq!(stack.tcp_retained(old), how != Refuse::Drop);
        peer.seq += 100;
        peer.syn(&mut stack, now, 1460);
        let new = info_of(&mut stack).id;
        assert_ne!(old, new);
        assert!(stack.tcp_retained(new));
        assert!(
            stack
                .poll_transmit_with(now, &mut [0; 1], TxCaps::NONE)
                .is_none()
        );
        assert_eq!(stack.tcp_retained(old), how != Refuse::Drop);
        if how != Refuse::Drop {
            let (tx, packet) = pull(&mut stack, now).unwrap();
            assert_eq!(tx.flow, Some(old));
            let ip = honk_netstack::wire::parse_ip(&packet).unwrap();
            assert_eq!(ip.proto, if how == Refuse::Rst { 6 } else { 1 });
        }
        assert!(!stack.tcp_retained(old));
        stack.tcp_close(old);
        assert!(stack.tcp_retained(new));
        stack.tcp_refuse(new, Refuse::Drop);
        assert!(!stack.tcp_retained(new));
    }
}

#[test]
fn rate_limited_refusal_releases_only_its_queued_local_obligation() {
    let now = Instant::now();
    let mut cfg = transparent();
    cfg.icmp_limits = IcmpLimits {
        per_sec: 1,
        burst: 1,
        target_burst: 1,
        ..IcmpLimits::default()
    };
    let mut stack = Stack::new(cfg, now);
    let mut peer = Peer::new(CLIENT, DST, 1000);
    peer.syn(&mut stack, now, 1460);
    let first = info_of(&mut stack).id;
    stack.tcp_refuse(first, Refuse::IcmpUnreachable);
    peer.seq += 100;
    peer.syn(&mut stack, now, 1460);
    let second = info_of(&mut stack).id;
    stack.tcp_refuse(second, Refuse::IcmpUnreachable);
    assert!(stack.tcp_retained(first) && stack.tcp_retained(second));
    assert_eq!(pull(&mut stack, now).unwrap().0.flow, Some(first));
    assert!(!stack.tcp_retained(first));
    assert!(stack.tcp_retained(second));
    assert!(pull(&mut stack, now).is_none());
    assert!(!stack.tcp_retained(second));
}

#[test]
fn reopened_tuple_does_not_reattribute_an_already_returned_packet() {
    let mut c = established(transparent(), AcceptOpts::default());
    let (closed, end, stamp) = enter_time_wait(&mut c);
    let old_fin = build(
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
    c.stack.receive(closed + ms(1), &old_fin);
    let old_output = pull(&mut c.stack, closed + ms(1)).unwrap().0;
    assert_eq!(old_output.flow, Some(c.id));
    c.peer.seq += 100_000;
    c.peer.ts += 100;
    c.peer.syn(&mut c.stack, closed + ms(2), 1460);
    let new = info_of(&mut c.stack).id;
    assert_ne!(new, c.id);
    assert!(!c.stack.tcp_retained(c.id));
    assert!(c.stack.tcp_retained(new));
    c.stack.tcp_accept(new, AcceptOpts::default()).unwrap();
    assert_eq!(
        pull(&mut c.stack, closed + ms(2)).unwrap().0.flow,
        Some(new)
    );
    assert_eq!(old_output.flow, Some(c.id));
    c.stack.tcp_close(c.id);
    assert!(c.stack.tcp_retained(new));
}

#[test]
fn known_handshake_reset_is_attributed_but_an_unknown_flow_reset_is_not() {
    let now = Instant::now();
    let mut cfg = Config::new([8; 32]);
    cfg.local_v4 = Some("10.0.0.1".parse().unwrap());
    let mut stack = Stack::new(cfg, now);
    let id = stack.tcp_connect(now, addr(DST)).unwrap();
    let (tx, packet) = pull(&mut stack, now).unwrap();
    assert_eq!(tx.flow, Some(id));
    let syn = decode(&packet);
    let bad_ack = build(
        syn.dst,
        syn.src,
        1000,
        syn.h.seq.wrapping_add(2),
        SYN | ACK,
        opts_syn(1460),
        &[],
    );
    assert_eq!(stack.receive(now + ms(1), &bad_ack), Rx::Consumed);
    let (tx, packet) = pull(&mut stack, now + ms(1)).unwrap();
    assert_eq!(tx.flow, Some(id));
    assert_eq!(decode(&packet).h.flags, RST);
    let unknown = build(
        addr("203.0.113.9:444"),
        syn.src,
        2000,
        1,
        ACK,
        Options::default(),
        &[],
    );
    assert_eq!(
        stack.receive(now + ms(2), &unknown),
        Rx::Dropped(DropReason::NoFlow)
    );
    let (tx, packet) = pull(&mut stack, now + ms(2)).unwrap();
    assert_eq!(tx.flow, None);
    assert_eq!(decode(&packet).h.flags, RST);
}
