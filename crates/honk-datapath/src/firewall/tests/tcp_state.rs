use super::*;
#[test]
fn tcp_requires_admitted_bidirectional_sequence_proof() {
    let now = Instant::now();
    let mut table = table();
    let tuple = tuple("10.0.0.2:1234", "192.0.2.9:443", 6);
    let bare_ack = Facts::parse(&tcp_packet(tuple, tcp::ACK, 11, 21)).unwrap();
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &bare_ack,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now
        }),
        Err(FirewallError::Denied)
    ));
    let syn = Facts::parse(&tcp_packet(tuple, tcp::SYN, 10, 0)).unwrap();
    let binding = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &syn,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    assert!(matches!(
        table.lookup(ingress(1), &bare_ack, now),
        Err(FirewallError::Denied)
    ));
    let reply = binding.after_route().reverse();
    let forged = Facts::parse(&tcp_packet(reply, tcp::SYN | tcp::ACK, 20, 99)).unwrap();
    assert!(matches!(
        table.lookup(ingress(2), &forged, now),
        Err(FirewallError::Denied)
    ));
    let synack = Facts::parse(&tcp_packet(reply, tcp::SYN | tcp::ACK, 20, 11)).unwrap();
    assert!(table.lookup(ingress(2), &synack, now).unwrap().is_some());
    assert!(table.lookup(ingress(1), &bare_ack, now).unwrap().is_some());
    assert!(matches!(table.entries[0].state, State::Established { .. }));
    assert!(matches!(
        table.lookup(ingress(1), &synack, now),
        Err(FirewallError::Denied)
    ));
}

#[test]
fn tcp_syn_data_and_simultaneous_open_retain_sequence_proof() {
    let now = Instant::now();
    let original = tuple("10.0.0.2:1234", "192.0.2.9:443", 6);
    for simultaneous in [false, true] {
        for payload in [&b""[..], &b"data"[..]] {
            let mut table = table();
            let client_end = 11 + payload.len() as u32;
            let server_end = 21 + payload.len() as u32;
            let syn = Facts::parse(&tcp_packet_data(original, tcp::SYN, 10, 0, payload)).unwrap();
            table
                .admit(Admission {
                    ingress: ingress(1),
                    reply_ingress: ingress(2),
                    facts: &syn,
                    dnat: None,
                    snat: SourceNat::None,
                    egress: None,
                    received_at: now,
                    now,
                })
                .unwrap();
            if simultaneous {
                let syn = Facts::parse(&tcp_packet_data(
                    original.reverse(),
                    tcp::SYN,
                    20,
                    0,
                    payload,
                ))
                .unwrap();
                table.lookup(ingress(2), &syn, now).unwrap().unwrap();
                let synack = Facts::parse(&tcp_packet_data(
                    original,
                    tcp::SYN | tcp::ACK,
                    10,
                    server_end,
                    payload,
                ))
                .unwrap();
                table.lookup(ingress(1), &synack, now).unwrap().unwrap();
            }
            let synack = Facts::parse(&tcp_packet_data(
                original.reverse(),
                tcp::SYN | tcp::ACK,
                20,
                client_end,
                payload,
            ))
            .unwrap();
            table.lookup(ingress(2), &synack, now).unwrap().unwrap();
            let ack =
                Facts::parse(&tcp_packet(original, tcp::ACK, client_end, server_end)).unwrap();
            table.lookup(ingress(1), &ack, now).unwrap().unwrap();
            // The final ACK can be lost after forwarding; the peer must still retry its handshake.
            assert!(table.lookup(ingress(2), &synack, now).unwrap().is_some());
            assert!(table.lookup(ingress(1), &syn, now).unwrap().is_some());
            let short =
                Facts::parse(&tcp_packet(original.reverse(), tcp::SYN | tcp::ACK, 20, 11)).unwrap();
            assert!(table.lookup(ingress(2), &short, now).unwrap().is_some());
            let reverse_syn = Facts::parse(&tcp_packet_data(
                original.reverse(),
                tcp::SYN,
                20,
                0,
                payload,
            ))
            .unwrap();
            assert_eq!(
                table.lookup(ingress(2), &reverse_syn, now).is_ok(),
                simultaneous
            );
            let forward_synack = Facts::parse(&tcp_packet_data(
                original,
                tcp::SYN | tcp::ACK,
                10,
                server_end,
                payload,
            ))
            .unwrap();
            assert_eq!(
                table.lookup(ingress(1), &forward_synack, now).is_ok(),
                simultaneous
            );
            for (flags, seq, ack, data) in [
                (tcp::SYN | tcp::ACK, 21, client_end, payload),
                (tcp::SYN | tcp::ACK, 20, client_end + 1, payload),
                (tcp::SYN | tcp::ACK, 20, client_end, &b"longer"[..]),
                (tcp::SYN | tcp::ACK | tcp::FIN, 20, client_end, payload),
                (tcp::SYN | tcp::ACK | tcp::RST, 20, client_end, payload),
            ] {
                let forged =
                    Facts::parse(&tcp_packet_data(original.reverse(), flags, seq, ack, data))
                        .unwrap();
                assert!(matches!(
                    table.lookup(ingress(2), &forged, now),
                    Err(FirewallError::Denied)
                ));
            }
            assert!(table.lookup(ingress(1), &ack, now).unwrap().is_some());
        }
    }
}
#[test]
fn tcp_established_and_udp_idle_timeouts_meet_rfc_minima() {
    let now = Instant::now();
    for protocol in [wire::PROTO_TCP, wire::PROTO_UDP] {
        let mut table = table();
        let original = tuple("10.0.0.2:1234", "192.0.2.9:443", protocol);
        let bytes = if protocol == wire::PROTO_TCP {
            tcp_packet(original, tcp::SYN, 10, 0)
        } else {
            udp(original)
        };
        let binding = table
            .admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &Facts::parse(&bytes).unwrap(),
                dnat: None,
                snat: SourceNat::None,
                egress: None,
                received_at: now,
                now,
            })
            .unwrap();
        if protocol == wire::PROTO_TCP {
            table
                .lookup(
                    ingress(2),
                    &Facts::parse(&tcp_packet(original.reverse(), tcp::SYN | tcp::ACK, 20, 11))
                        .unwrap(),
                    now,
                )
                .unwrap()
                .unwrap();
            table
                .lookup(
                    ingress(1),
                    &Facts::parse(&tcp_packet(original, tcp::ACK, 11, 21)).unwrap(),
                    now,
                )
                .unwrap()
                .unwrap();
        }
        let ttl = Duration::from_secs(if protocol == wire::PROTO_TCP {
            7440
        } else {
            120
        });
        table.expire(now + ttl - Duration::from_nanos(1));
        assert!(binding.is_active());
        table.expire(now + ttl);
        assert!(!binding.is_active());
    }
}

#[test]
fn unauthenticated_fin_and_rst_do_not_shorten_established_lifetime() {
    let now = Instant::now();
    let original = tuple("10.0.0.2:1234", "192.0.2.9:443", wire::PROTO_TCP);
    for (flags, sequence, acknowledgment) in [
        (tcp::RST, 0x8000_0000, 0),
        (tcp::RST | tcp::ACK, 0x8000_0000, 0x8000_0000),
        (tcp::FIN | tcp::ACK, 0x8000_0000, 0x8000_0000),
    ] {
        let mut table = table();
        let binding = table
            .admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &Facts::parse(&tcp_packet(original, tcp::SYN, 10, 0)).unwrap(),
                dnat: None,
                snat: snat(),
                egress: None,
                received_at: now,
                now,
            })
            .unwrap();
        let reply = binding.after_route().reverse();
        table
            .lookup(
                ingress(2),
                &Facts::parse(&tcp_packet(reply, tcp::SYN | tcp::ACK, 20, 11)).unwrap(),
                now,
            )
            .unwrap()
            .unwrap();
        table
            .lookup(
                ingress(1),
                &Facts::parse(&tcp_packet(original, tcp::ACK, 11, 21)).unwrap(),
                now,
            )
            .unwrap()
            .unwrap();
        let forged = Facts::parse(&tcp_packet(reply, flags, sequence, acknowledgment)).unwrap();
        table.lookup(ingress(2), &forged, now).unwrap().unwrap();
        let later = now + Duration::from_secs(31);
        table.expire(later);
        let mut packet = tcp_packet_data(original, tcp::ACK | tcp::PSH, 11, 21, b"still live");
        let lease = table
            .lookup(ingress(1), &Facts::parse(&packet).unwrap(), later)
            .unwrap()
            .unwrap();
        lease.rewrite(&mut packet, false).unwrap();
        assert!(binding.is_active());
        assert_eq!(Facts::parse(&packet).unwrap().tuple, binding.after_route());
        assert_eq!(&packet[40..], b"still live");
    }
}
