use super::*;
use honk_netstack::MemoryBudget;

#[test]
fn duplicate_syn_output_cannot_postpone_passive_handshake_timeout() {
    let t0 = Instant::now();
    let budget = MemoryBudget::new(128 * 1024);
    let mut cfg = transparent();
    cfg.shared_budget = Some(budget.clone());
    let mut stack = Stack::new(cfg, t0);
    let peer = Peer::new(CLIENT, DST, 1000);
    assert_eq!(peer.syn(&mut stack, t0, 1460), Rx::Consumed);
    let info = info_of(&mut stack);
    stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
    assert_eq!(drain(&mut stack, t0).len(), 1);
    for tick in 1..=400 {
        let now = t0 + Duration::from_millis(tick * 500);
        while let Some(at) = stack.poll_timeout().filter(|&at| at <= now) {
            stack.handle_timeout(at);
            drain(&mut stack, at);
        }
        if stack.tcp_state(info.id) == Some(TcpState::Closed) {
            break;
        }
        assert_eq!(peer.syn(&mut stack, now, 1460), Rx::Consumed);
        assert_eq!(drain(&mut stack, now).len(), 1);
        assert!(stack.poll_accept().is_none());
    }
    assert_eq!(
        stack.tcp_read(info.id, &mut [0; 1]),
        Err(StreamError::TimedOut)
    );
    assert_eq!(stack.stats().half_open, 0);
    stack.tcp_close(info.id);
    assert_eq!(stack.stats().flows, 0);
    assert_eq!(budget.used(), 0);
}

#[test]
fn refusal_window_tracks_actual_passive_syn_ack_output() {
    let variants = [
        Refuse::Drop,
        Refuse::Rst,
        Refuse::IcmpUnreachable,
        Refuse::IcmpAdminProhibited,
    ];
    for deferred in [false, true] {
        for blocked in [false, true] {
            for how in variants {
                let t0 = Instant::now();
                let budget = MemoryBudget::new(128 * 1024);
                let mut cfg = transparent();
                cfg.shared_budget = Some(budget.clone());
                let mut stack = Stack::new(cfg, t0);
                let peer = Peer::new(CLIENT, DST, 1000);
                peer.syn(&mut stack, t0, 1460);
                let info = info_of(&mut stack);
                stack.tcp_accept(info.id, AcceptOpts {
                    when: if deferred {
                        AcceptWhen::Deferred { deadline: Duration::from_secs(5) }
                    } else {
                        AcceptWhen::Now
                    },
                    ..AcceptOpts::default()
                }).unwrap();
                if deferred {
                    stack.tcp_complete(info.id).unwrap();
                }
                if blocked {
                    assert!(stack.poll_transmit(t0, &mut [0; 1]).is_none());
                }
                stack.tcp_refuse(info.id, how);
                assert_eq!((stack.stats().flows, stack.stats().half_open), (0, 0));
                assert_eq!(budget.used(), 0);
                assert_eq!(stack.tcp_read(info.id, &mut [0; 1]), Err(StreamError::Stale));
                let packets = drain_raw(&mut stack, t0);
                if how == Refuse::Drop {
                    assert!(packets.is_empty());
                } else {
                    assert_eq!(packets.len(), 1);
                    if how == Refuse::Rst {
                        assert_eq!(decode(&packets[0]).h.flags, RST | ACK);
                    } else {
                        let ip = honk_netstack::wire::parse_ip(&packets[0]).unwrap();
                        assert_eq!(ip.proto, honk_netstack::wire::PROTO_ICMP);
                        let icmp = &packets[0][ip.payload];
                        assert_eq!((icmp[0], icmp[1]), (3, if how == Refuse::IcmpUnreachable { 1 } else { 13 }));
                    }
                }
            }
        }
    }
    for how in variants {
        let t0 = Instant::now();
        let mut stack = Stack::new(transparent(), t0);
        Peer::new(CLIENT, DST, 1000).syn(&mut stack, t0, 1460);
        let info = info_of(&mut stack);
        stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
        assert_eq!(drain(&mut stack, t0).len(), 1);
        stack.tcp_refuse(info.id, how);
        assert_eq!(stack.tcp_state(info.id), Some(TcpState::SynReceived));
        assert_eq!((stack.stats().flows, stack.stats().half_open), (1, 1));
        assert!(drain_raw(&mut stack, t0).is_empty());

        let mut cfg = transparent();
        cfg.local_v4 = Some("10.0.0.1".parse().unwrap());
        let mut active = Stack::new(cfg, t0);
        let id = active.tcp_connect(t0, addr(DST)).unwrap();
        active.tcp_refuse(id, how);
        assert_eq!(active.tcp_state(id), Some(TcpState::SynSent));
        let packets = drain(&mut active, t0);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].h.flags, SYN);
    }
}
