use super::*;
use honk_netstack::MemoryBudget;
use honk_netstack::wire;

fn set_dscp(packet: &mut [u8], dscp: u8, ecn: u8) {
    let traffic_class = dscp << 2 | ecn;
    if packet[0] >> 4 == 6 {
        packet[0] = 0x60 | traffic_class >> 4;
        packet[1] = traffic_class << 4 | (packet[1] & 0x0F);
    } else {
        packet[1] = traffic_class;
        packet[10..12].fill(0);
        let header = usize::from(packet[0] & 0x0F) * 4;
        let checksum = wire::checksum::checksum(&packet[..header]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
}

#[test]
fn syn_dscp_comes_from_the_first_valid_admission_not_retransmissions() {
    for (src, dst) in [(CLIENT, DST), ("[fd00::2]:40000", "[2001:db8::9]:443")] {
        for dscp in [0, 46] {
            let now = Instant::now();
            let mut stack = Stack::new(transparent(), now);
            let mut syn = build(addr(src), addr(dst), 1000, 0, SYN, opts_syn(1460), &[]);
            set_dscp(&mut syn, dscp, 3);
            let mut retry = syn.clone();
            set_dscp(&mut retry, 46 - dscp, 1);
            let mut forged = retry.clone();
            forged[wire::ip_header_len(addr(src).is_ipv6()) + 16] ^= 1;
            assert_eq!(
                stack.receive(now, &forged),
                Rx::Dropped(DropReason::Checksum)
            );
            assert!(stack.poll_accept().is_none());
            if addr(src).is_ipv4() {
                let mut bad_header = retry.clone();
                bad_header[1] ^= 4;
                assert_eq!(
                    stack.receive(now, &bad_header),
                    Rx::Dropped(DropReason::Checksum)
                );
                assert!(stack.poll_accept().is_none());
            }
            assert_eq!(stack.receive(now, &syn), Rx::Consumed);
            assert_eq!(stack.receive(now + ms(1), &retry), Rx::Consumed);
            assert_eq!(
                stack.receive(now + ms(2), &forged),
                Rx::Dropped(DropReason::Checksum)
            );
            let info = info_of(&mut stack);
            assert_eq!(
                (info.client, info.original_dst, info.dscp),
                (addr(src), addr(dst), dscp)
            );
            assert_eq!((stack.stats().flows, stack.stats().half_open), (1, 1));
            assert!(stack.poll_accept().is_none());
            assert!(drain(&mut stack, now + ms(2)).is_empty());
            stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
            assert_eq!(drain(&mut stack, now + ms(2))[0].h.flags, SYN | ACK);
        }
    }
}

fn fragment_packet(whole: &[u8], first: bool) -> Vec<u8> {
    let ip = wire::parse_ip(whole).unwrap();
    let data = &whole[ip.payload.clone()];
    let (offset, data) = if first {
        (0, &data[..16])
    } else {
        (16, &data[16..])
    };
    let mut packet = whole[..ip.payload.start].to_vec();
    if ip.src.is_ipv6() {
        packet[4..6].copy_from_slice(&((data.len() + 8) as u16).to_be_bytes());
        packet[6] = 44;
        packet.extend_from_slice(&[ip.proto, 0]);
        packet.extend_from_slice(&((offset as u16) | u16::from(first)).to_be_bytes());
        packet.extend_from_slice(&17u32.to_be_bytes());
    } else {
        let total = (packet.len() + data.len()) as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[4..6].copy_from_slice(&17u16.to_be_bytes());
        let field = (offset / 8) as u16 | if first { 0x2000 } else { 0 };
        packet[6..8].copy_from_slice(&field.to_be_bytes());
    }
    packet.extend_from_slice(data);
    set_dscp(&mut packet, ip.dscp, 3);
    packet
}

#[test]
fn reassembled_syn_dscp_uses_fragment_zero_header_in_either_arrival_order() {
    for (src, dst) in [(CLIENT, DST), ("[fd00::2]:40000", "[2001:db8::9]:443")] {
        for dscp in [0, 46] {
            for reverse in [false, true] {
                let now = Instant::now();
                let mut stack = Stack::new(transparent(), now);
                let mut syn = build(addr(src), addr(dst), 1000, 0, SYN, opts_syn(1460), &[]);
                set_dscp(&mut syn, dscp, 3);
                let mut fragments = [fragment_packet(&syn, true), fragment_packet(&syn, false)];
                set_dscp(&mut fragments[1], 46 - dscp, 1);
                if reverse {
                    fragments.reverse();
                }
                assert_eq!(stack.receive(now, &fragments[0]), Rx::Consumed);
                assert!(stack.poll_accept().is_none());
                assert_eq!(stack.receive(now, &fragments[1]), Rx::Consumed);
                let info = info_of(&mut stack);
                assert_eq!(
                    (info.client, info.original_dst, info.dscp),
                    (addr(src), addr(dst), dscp)
                );
                assert!(stack.poll_accept().is_none());
                stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
                assert_eq!(drain(&mut stack, now)[0].h.flags, SYN | ACK);
            }
        }
    }
}

#[test]
fn transparent_udp_variants_preserve_wire_dscp_for_both_families() {
    use honk_netstack::{Csum, GsoKind, GsoRx, RxMeta};

    for (src, dst) in [(CLIENT, DST), ("[fd00::2]:40000", "[2001:db8::9]:443")] {
        let (src, dst) = (addr(src), addr(dst));
        for dscp in [0, 46] {
            let now = Instant::now();
            let mut stack = Stack::new(transparent(), now);
            let data = [73; 40];
            let mut packet = vec![0; data.len() + 64];
            let n = wire::udp::emit_packet(&mut packet, src, dst, &data).unwrap();
            packet.truncate(n);
            set_dscp(&mut packet, dscp, 3);
            let mut forged = packet.clone();
            forged[wire::ip_header_len(src.is_ipv6()) + 6] ^= 1;
            assert_eq!(
                stack.receive(now, &forged),
                Rx::Dropped(DropReason::Checksum)
            );
            let Rx::Transparent {
                src: got_src,
                dst: got_dst,
                dscp: got_dscp,
                payload,
            } = stack.receive(now, &packet)
            else {
                panic!("ordinary UDP datagram must borrow its input")
            };
            assert_eq!((got_src, got_dst, got_dscp), (src, dst, dscp));
            assert_eq!(packet[payload], data);
            let meta = RxMeta {
                csum: Csum::Verify,
                gso: Some(GsoRx {
                    kind: GsoKind::UdpL4,
                    size: 16,
                }),
            };
            let Rx::TransparentSplit {
                src: got_src,
                dst: got_dst,
                dscp: got_dscp,
                payload,
                size,
            } = stack.receive_with(now, &packet, meta)
            else {
                panic!("USO datagram must retain DSCP alongside its boundaries")
            };
            assert_eq!((got_src, got_dst, got_dscp, size), (src, dst, dscp, 16));
            assert_eq!(
                packet[payload]
                    .chunks(usize::from(size))
                    .map(<[u8]>::len)
                    .collect::<Vec<_>>(),
                [16, 16, 8]
            );
            for reverse in [false, true] {
                let mut fragments = [
                    fragment_packet(&packet, true),
                    fragment_packet(&packet, false),
                ];
                set_dscp(&mut fragments[1], 46 - dscp, 1);
                if reverse {
                    fragments.reverse();
                }
                assert_eq!(stack.receive(now, &fragments[0]), Rx::Consumed);
                let Rx::TransparentOwned {
                    src: got_src,
                    dst: got_dst,
                    dscp: got_dscp,
                    packet: owned,
                    payload,
                } = stack.receive(now, &fragments[1])
                else {
                    panic!("reassembled UDP datagram must own its input")
                };
                assert_eq!((got_src, got_dst, got_dscp), (src, dst, dscp));
                assert_eq!(wire::parse_ip(&owned).unwrap().dscp, dscp);
                assert_eq!(owned[payload], data);
            }
        }
    }
}

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
                stack
                    .tcp_accept(
                        info.id,
                        AcceptOpts {
                            when: if deferred {
                                AcceptWhen::Deferred {
                                    deadline: Duration::from_secs(5),
                                }
                            } else {
                                AcceptWhen::Now
                            },
                            ..AcceptOpts::default()
                        },
                    )
                    .unwrap();
                if deferred {
                    stack.tcp_complete(info.id).unwrap();
                }
                if blocked {
                    assert!(stack.poll_transmit(t0, &mut [0; 1]).is_none());
                }
                stack.tcp_refuse(info.id, how);
                assert_eq!((stack.stats().flows, stack.stats().half_open), (0, 0));
                assert_eq!(budget.used(), 0);
                assert_eq!(
                    stack.tcp_read(info.id, &mut [0; 1]),
                    Err(StreamError::Stale)
                );
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
                        assert_eq!(
                            (icmp[0], icmp[1]),
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

#[test]
fn ipv4_mapped_ipv6_wire_addresses_cannot_alias_ipv4_endpoints() {
    let now = Instant::now();
    for (source, destination) in [
        ("[::ffff:10.0.0.2]:40000", "[2001:db8::9]:443"),
        ("[fd00::2]:40000", "[::ffff:203.0.113.9]:443"),
    ] {
        let mut stack = Stack::new(transparent(), now);
        let mut packet = [0; 128];
        let length =
            wire::udp::emit_packet(&mut packet, addr(source), addr(destination), b"scoped")
                .unwrap();
        assert_eq!(
            stack.receive(now, &packet[..length]),
            Rx::Dropped(honk_netstack::DropReason::Unsupported)
        );
    }
}
