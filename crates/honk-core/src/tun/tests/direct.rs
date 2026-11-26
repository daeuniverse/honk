use super::*;
use honk_netstack::{DropReason, GsoTx, Rx, Stack};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::task::Waker;
use tokio::io::AsyncWriteExt;

const CLIENT: &str = "192.0.2.1:41000";
const SERVER: &str = "198.51.100.1:443";

fn tx(len: usize) -> Transmit {
    Transmit {
        len,
        gso: None,
        csum: TxCsum::Full,
        flow: None,
        source: None,
    }
}

fn segment(client: SocketAddr, server: SocketAddr, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut packet = vec![0; 128];
    let n = wire::tcp::emit_packet(
        &mut packet,
        client.ip(),
        server.ip(),
        &wire::tcp::Header {
            src_port: client.port(),
            dst_port: server.port(),
            seq,
            ack,
            flags,
            window: u16::MAX,
            urgent: 0,
            options: wire::tcp::Options::default(),
        },
        [&[], &[]],
    )
    .unwrap();
    packet.truncate(n);
    packet
}

fn datagram_pair() -> (AsyncFd<UnixDatagram>, UnixDatagram) {
    let (writer, reader) = UnixDatagram::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    reader.set_nonblocking(true).unwrap();
    // SAFETY: the socket keeps its descriptor until deregistration.
    (unsafe { AsyncFd::register(writer) }.unwrap(), reader)
}

async fn stop_driven(
    endpoints: PacketEndpoints,
    mut owner: PacketEndpointOwner,
    mut driver: PacketDriver,
    scope: PacketScope,
    budget: Arc<MemoryBudget>,
) {
    endpoints.close();
    let (plane, result) = poll_fn(|cx| {
        service_turn(
            std::slice::from_mut(&mut driver),
            cx,
            Instant::now(),
            |_, _| Ok(false),
        )
        .unwrap();
        owner.poll_join_plane(cx)
    })
    .await
    .unwrap();
    result.unwrap();
    drop((plane, endpoints, owner, driver, scope));
    assert_eq!(budget.used(), 0);
}

#[test]
fn scatter_vnet_checks_logical_tcp_extents_and_offload_fields() {
    for (client, server) in [
        (CLIENT, SERVER),
        ("[2001:db8::1]:41000", "[2001:db8::2]:443"),
    ] {
        let mut packet = segment(
            client.parse().unwrap(),
            server.parse().unwrap(),
            7,
            4,
            wire::tcp::ACK,
        );
        let ipv6 = packet[0] >> 4 == 6;
        let mut start = if ipv6 { 40 } else { 20 };
        if ipv6 {
            // Include both an extension walker and an IP/TCP boundary different from the base header.
            packet[6] = 60;
            packet.splice(40..40, [wire::PROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
            start += 8;
        } else {
            packet[0] = 0x46;
            packet.splice(20..20, [1, 1, 1, 0]);
            start += 4;
        }
        let hdr_len = packet.len();
        let logical = hdr_len + 7;
        if ipv6 {
            packet[4..6].copy_from_slice(&((logical - 40) as u16).to_be_bytes());
        } else {
            packet[2..4].copy_from_slice(&(logical as u16).to_be_bytes());
            packet[10..12].fill(0);
            let sum = wire::checksum::checksum(&packet[..start]);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        let full = tx(logical);
        assert_eq!(
            vnet_header_iov(&packet, logical, full).unwrap(),
            [0; VNET_BYTES]
        );
        let partial = Transmit {
            csum: TxCsum::Partial {
                start: start as u16,
                offset: 16,
            },
            ..full
        };
        let expected = [1, 0, 0, 0, 0, 0, start as u8, 0, 16, 0];
        assert_eq!(
            vnet_header_iov(&packet, logical, partial).unwrap(),
            expected
        );
        let gso = GsoTx {
            kind: GsoKind::Tcp,
            size: 3,
            hdr_len: hdr_len as u16,
        };
        let tso = Transmit {
            gso: Some(gso),
            ..partial
        };
        let mut expected = expected;
        expected[1] = if ipv6 { 4 } else { 1 };
        expected[2] = hdr_len as u8;
        expected[4] = 3;
        assert_eq!(vnet_header_iov(&packet, logical, tso).unwrap(), expected);
        for bad in [
            Transmit {
                gso: Some(gso),
                ..full
            },
            Transmit {
                csum: TxCsum::Partial {
                    start: (start - 1) as u16,
                    offset: 16,
                },
                ..partial
            },
            Transmit {
                csum: TxCsum::Partial {
                    start: start as u16,
                    offset: 6,
                },
                ..partial
            },
            Transmit {
                len: logical + 1,
                ..partial
            },
            Transmit {
                gso: Some(GsoTx {
                    kind: GsoKind::UdpL4,
                    ..gso
                }),
                ..tso
            },
            Transmit {
                gso: Some(GsoTx { size: 0, ..gso }),
                ..tso
            },
            Transmit {
                gso: Some(GsoTx { size: 7, ..gso }),
                ..tso
            },
            Transmit {
                gso: Some(GsoTx {
                    size: u16::MAX,
                    ..gso
                }),
                ..tso
            },
            Transmit {
                gso: Some(GsoTx {
                    hdr_len: gso.hdr_len + 1,
                    ..gso
                }),
                ..tso
            },
        ] {
            assert_eq!(
                vnet_header_iov(&packet, logical, bad).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert!(vnet_header_iov(&packet[..hdr_len - 1], logical, full).is_err());
        assert!(vnet_header_iov(&packet, logical + 1, tx(logical + 1)).is_err());
        packet[start + 12] = 0x40;
        assert!(vnet_header_iov(&packet, logical, full).is_err());
        packet[0] = 0;
        assert!(vnet_header_iov(&packet, logical, full).is_err());
    }
}

#[test]
fn scatter_vnet_accepts_stack_udp_fragments_and_icmp_for_both_families() {
    for (src, dst) in [
        (CLIENT, SERVER),
        ("[2001:db8::1]:41000", "[2001:db8::2]:443"),
    ] {
        let src: SocketAddr = src.parse().unwrap();
        let dst: SocketAddr = dst.parse().unwrap();
        let now = Instant::now();
        let mut cfg = honk_netstack::Config::new([3; 32]);
        cfg.mtu = 1280;
        cfg.mode = honk_netstack::Mode::Transparent {
            exclude: Default::default(),
        };
        let mut stack = Stack::new(cfg, now);
        let mut buf = [0; 1280];
        let ip_len = if src.is_ipv6() { 40 } else { 20 };
        let n = stack.udp_send_from(src, dst, b"udp", &mut buf).unwrap();
        let udp_header = &buf[..ip_len + 8];
        assert_eq!(
            vnet_header_iov(udp_header, n, tx(n)).unwrap(),
            [0; VNET_BYTES]
        );
        let udp_partial = Transmit {
            csum: TxCsum::Partial {
                start: ip_len as u16,
                offset: 6,
            },
            ..tx(n)
        };
        assert_eq!(
            vnet_header_iov(udp_header, n, udp_partial).unwrap(),
            [1, 0, 0, 0, 0, 0, ip_len as u8, 0, 6, 0]
        );
        let quote = buf[..n].to_vec();
        let n = stack
            .udp_refuse(
                now,
                honk_netstack::UdpRefuse::PortUnreachable,
                &quote,
                &mut buf,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            vnet_header_iov(&buf[..ip_len + 8], n, tx(n)).unwrap(),
            [0; VNET_BYTES]
        );
        let icmp_partial = Transmit {
            len: n,
            ..udp_partial
        };
        assert!(vnet_header_iov(&buf[..ip_len + 8], n, icmp_partial).is_err());

        let mut n = stack.udp_send_from(src, dst, &[5; 3000], &mut buf).unwrap();
        let fragment_head = ip_len + usize::from(src.is_ipv6()) * 8;
        let mut fragments = 0;
        loop {
            assert_eq!(
                vnet_header_iov(&buf[..fragment_head], n, tx(n)).unwrap(),
                [0; VNET_BYTES]
            );
            assert!(vnet_header_iov(&buf[..fragment_head - 1], n, tx(n)).is_err());
            assert!(
                vnet_header_iov(
                    &buf[..fragment_head],
                    n,
                    Transmit {
                        len: n,
                        ..udp_partial
                    }
                )
                .is_err()
            );
            if src.is_ipv6() {
                let mut extended = [0; 56];
                extended[..40].copy_from_slice(&buf[..40]);
                extended[4..6].copy_from_slice(&((n - 40 + 8) as u16).to_be_bytes());
                extended[6] = 60;
                extended[40] = 44;
                extended[48..].copy_from_slice(&buf[40..48]);
                assert_eq!(
                    vnet_header_iov(&extended, n + 8, tx(n + 8)).unwrap(),
                    [0; VNET_BYTES]
                );
                extended[49] = 1;
                assert!(vnet_header_iov(&extended, n + 8, tx(n + 8)).is_err());
            }
            fragments += 1;
            let Some(next) = stack.poll_transmit(now, &mut buf) else {
                break;
            };
            n = next;
        }
        assert_eq!(fragments, 3);
    }
}

#[test]
fn scatter_writev_sends_one_exact_record_and_checks_its_iovec_bound() {
    let (writer, reader) = UnixDatagram::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    let src = SERVER.parse().unwrap();
    let dst = CLIENT.parse().unwrap();
    let payload: Vec<_> = (0..18).collect();
    let mut packet = [0; 128];
    let len = wire::udp::emit_packet(&mut packet, src, dst, &payload).unwrap();
    let header = &packet[..28];
    let parts: Vec<_> = payload.iter().map(std::slice::from_ref).collect();
    write_packet_iov(writer.as_raw_fd(), header, &parts, tx(len)).unwrap();
    let expected = [&[0; VNET_BYTES][..], &packet[..len]].concat();
    let mut received = [0; 128];
    let n = reader.recv(&mut received).unwrap();
    assert_eq!(&received[..n], expected);
    let mut with_empty = parts.clone();
    with_empty[0] = &[];
    assert!(write_packet_iov(writer.as_raw_fd(), header, &with_empty, tx(len)).is_err());
    with_empty[1] = &payload[..2];
    write_packet_iov(writer.as_raw_fd(), header, &with_empty, tx(len)).unwrap();
    let n = reader.recv(&mut received).unwrap();
    assert_eq!(&received[..n], expected);
    with_empty.push(&[]);
    assert!(write_packet_iov(writer.as_raw_fd(), header, &with_empty, tx(len)).is_err());
    assert_eq!(
        reader.recv(&mut received).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn standalone_turn_writes_after_rx_and_recovers_borrowed_tcp_and_udp_credit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (endpoints, owner, mut driver, scope, budget) = driven_endpoints().await;
        let (writer, reader) = datagram_pair();
        drop(writer.writable().await.unwrap());
        let mut cx = Context::from_waker(Waker::noop());
        let mut first = 0;
        let client = CLIENT.parse().unwrap();
        let server = SERVER.parse().unwrap();
        let now = Instant::now() + Duration::from_secs(10);
        let mut flow = None;
        let mut record = [0; RX_BYTES];
        service_turn(
            std::slice::from_mut(&mut driver),
            &mut cx,
            now,
            |drivers, cx| {
                assert_eq!(
                    scope.receive(&segment(client, server, 19, 0, wire::tcp::SYN), now),
                    Rx::Consumed
                );
                flow = Some(scope.poll_accept().unwrap().1);
                assert!(scope.poll_output(cx).is_pending());
                Ok(poll_outputs(&writer, drivers, &mut first, cx, now, || {
                    true
                })?)
            },
        )
        .unwrap();
        let length = reader.recv(&mut record).unwrap();
        let (packet, _) = decode_record(&record[..length]).unwrap();
        let ip = wire::parse_ip(packet).unwrap();
        let synack = wire::tcp::parse(&packet[ip.payload]).unwrap().0;
        assert_eq!(synack.flags, wire::tcp::SYN | wire::tcp::ACK);
        let seq = synack.seq.wrapping_add(1);
        let now = now + Duration::from_micros(1);
        assert_eq!(
            scope.receive(&segment(client, server, 20, seq, wire::tcp::ACK), now),
            Rx::Consumed
        );
        let mut flow = flow.unwrap();
        let payload: Vec<_> = (0..9_000).map(|n| (n % 251) as u8).collect();
        flow.write_all(&payload).await.unwrap();
        let id = flow.flow_id();
        let mut received = 0;
        let mut saw_scatter_tso = false;
        let mut now = now;
        for _ in 0..32 {
            let mut offered = received;
            service_turn(
                std::slice::from_mut(&mut driver),
                &mut cx,
                now,
                |drivers, cx| {
                    assert!(
                        scope.poll_output(cx).is_pending(),
                        "protocol output stays in the send ring"
                    );
                    Ok(write_output_turn(
                        drivers,
                        &mut first,
                        now,
                        || true,
                        |header, parts, tx| {
                            assert_eq!(tx.flow, Some(id));
                            assert!(matches!(tx.csum, TxCsum::Partial { offset: 16, .. }));
                            let start = offered;
                            for part in parts {
                                let end = offered + part.len();
                                assert_eq!(*part, &payload[offered..end]);
                                offered = end;
                            }
                            assert!(offered > start);
                            assert_eq!(header.len() + offered - start, tx.len);
                            saw_scatter_tso |= parts.len() >= 2 && tx.gso.is_some();
                            write_packet_iov(writer.get_ref().as_raw_fd(), header, parts, tx)
                        },
                    )?)
                },
            )
            .unwrap();
            let before = received;
            while received < offered {
                let length = reader.recv(&mut record).unwrap();
                let (packet, meta) = decode_record(&record[..length]).unwrap();
                assert!(matches!(meta.csum, Csum::Partial { offset: 16, .. }));
                if let Some(gso) = meta.gso {
                    assert_eq!(gso.kind, GsoKind::Tcp);
                }
                let ip = wire::parse_ip(packet).unwrap();
                let (header, hlen) = wire::tcp::parse(&packet[ip.payload.clone()]).unwrap();
                assert_eq!(header.seq, seq.wrapping_add(received as u32));
                let data = &packet[ip.payload.start + hlen..];
                assert!(!data.is_empty());
                assert_eq!(data, &payload[received..received + data.len()]);
                received += data.len();
            }
            assert_eq!(received, offered);
            now += Duration::from_millis(1);
            if received != before {
                assert_eq!(
                    scope.receive(
                        &segment(
                            client,
                            server,
                            20,
                            seq.wrapping_add(received as u32),
                            wire::tcp::ACK
                        ),
                        now
                    ),
                    Rx::Consumed
                );
            }
            if received == payload.len() {
                break;
            }
        }
        assert_eq!(received, payload.len());
        assert!(
            saw_scatter_tso,
            "device must consume a TSO record borrowed from multiple ring chunks"
        );

        let sender = scope.datagram_sender(server);
        for token in 0..4 {
            sender.send_to(&[token], client).await.unwrap();
        }
        {
            let blocked = sender.send_to(b"after-credit", client);
            tokio::pin!(blocked);
            assert!(futures::poll!(&mut blocked).is_pending());
            service_turn(
                std::slice::from_mut(&mut driver),
                &mut cx,
                now,
                |drivers, cx| {
                    Ok(poll_outputs(&writer, drivers, &mut first, cx, now, || {
                        true
                    })?)
                },
            )
            .unwrap();
            assert_eq!(blocked.await.unwrap(), b"after-credit".len());
        }
        for token in 0..4 {
            let n = reader.recv(&mut record).unwrap();
            assert_eq!(record[n - 1], token);
        }
        drop((flow, sender));
        stop_driven(endpoints, owner, driver, scope, budget).await;
    })
    .await
    .expect("normal TUN turn must return scope credit after one complete record");
}

#[tokio::test]
async fn standalone_eagain_registers_writable_and_retries_the_uncommitted_fragment() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (endpoints, owner, mut driver, scope, budget) = driven_endpoints().await;
        let (writer, reader) = datagram_pair();
        drop(writer.writable().await.unwrap());
        let payload = vec![0x53; 1800];
        scope
            .datagram_sender(SERVER.parse().unwrap())
            .send_to(&payload, CLIENT.parse().unwrap())
            .await
            .unwrap();
        let mut first = 0;
        let now = Instant::now() + Duration::from_secs(10);
        let mut record = [0; RX_BYTES];
        // Accept the CPU first fragment, then block the scatter continuation on stale readiness.
        write_output_turn(
            std::slice::from_mut(&mut driver),
            &mut first,
            now,
            || true,
            |header, parts, tx| {
                if parts.is_empty() {
                    write_packet_iov(writer.get_ref().as_raw_fd(), header, parts, tx)
                } else {
                    Err(io::ErrorKind::WouldBlock.into())
                }
            },
        )
        .unwrap_err();
        let first_len = reader.recv(&mut record).unwrap();
        assert!(first_len > 1_000);
        let filler = [0x2e; 1024];
        loop {
            match writer.get_ref().send(&filler) {
                Ok(n) => assert_eq!(n, filler.len()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("socket fill failed: {error}"),
            }
        }
        let before = scope.stats().unwrap().tx_packets;
        let used = budget.used();
        {
            let retry = poll_fn(|cx| {
                let more =
                    service_turn(std::slice::from_mut(&mut driver), cx, now, |drivers, cx| {
                        Ok(poll_outputs(&writer, drivers, &mut first, cx, now, || {
                            true
                        })?)
                    })
                    .unwrap();
                if scope.stats().unwrap().tx_packets != before {
                    Poll::Ready(())
                } else {
                    assert!(!more, "EAGAIN must clear the stale readiness and park");
                    Poll::Pending
                }
            });
            tokio::pin!(retry);
            assert!(futures::poll!(&mut retry).is_pending());
            assert_eq!(scope.stats().unwrap().tx_packets, before);
            assert_eq!(budget.used(), used);
            loop {
                match reader.recv(&mut record) {
                    Ok(n) => assert_eq!(&record[..n], filler),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("socket drain failed: {error}"),
                }
            }
            retry.await;
        }
        assert_eq!(scope.stats().unwrap().tx_packets, before + 1);
        assert!(
            budget.used() < used,
            "the accepted final fragment returns its charge"
        );
        let n = reader.recv(&mut record).unwrap();
        let (packet, _) = decode_record(&record[..n]).unwrap();
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        assert_eq!(usize::from(fragment) * 8, first_len - VNET_BYTES - 20);
        assert!(packet[20..].iter().all(|&byte| byte == 0x53));
        assert_eq!(
            reader.recv(&mut record).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        stop_driven(endpoints, owner, driver, scope, budget).await;
    })
    .await
    .expect("writability alone must resume the blocked direct driver");
}

#[tokio::test]
async fn standalone_positive_short_write_is_fatal_without_replay() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (endpoints, owner, mut driver, scope, budget) = driven_endpoints().await;
        let (writer, reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        nix::sys::socket::setsockopt(&writer, nix::sys::socket::sockopt::SndBuf, &1024).unwrap();
        // SAFETY: the writer keeps the same socket until deregistration.
        let writer = unsafe { AsyncFd::register(writer) }.unwrap();
        drop(writer.writable().await.unwrap());
        let mut cx = Context::from_waker(Waker::noop());
        let mut first = 0;
        let now = Instant::now() + Duration::from_secs(10);
        let client = CLIENT.parse().unwrap();
        let server = SERVER.parse().unwrap();
        // Use the datagram writer to establish the flow before exercising a true short write.
        let (setup, setup_peer) = datagram_pair();
        drop(setup.writable().await.unwrap());
        assert_eq!(
            scope.receive(&segment(client, server, 19, 0, wire::tcp::SYN), now),
            Rx::Consumed
        );
        let mut flow = scope.poll_accept().unwrap().1;
        service_turn(
            std::slice::from_mut(&mut driver),
            &mut cx,
            now,
            |drivers, cx| Ok(poll_outputs(&setup, drivers, &mut first, cx, now, || true)?),
        )
        .unwrap();
        let mut record = [0; RX_BYTES];
        let n = setup_peer.recv(&mut record).unwrap();
        let (packet, _) = decode_record(&record[..n]).unwrap();
        let ip = wire::parse_ip(packet).unwrap();
        let synack = wire::tcp::parse(&packet[ip.payload]).unwrap().0;
        let seq = synack.seq.wrapping_add(1);
        let now = now + Duration::from_micros(1);
        assert_eq!(
            scope.receive(&segment(client, server, 20, seq, wire::tcp::ACK), now),
            Rx::Consumed
        );
        flow.write_all(&[0x7c; 9_000]).await.unwrap();
        let before = scope.stats().unwrap().tx_packets;
        let error = service_turn(
            std::slice::from_mut(&mut driver),
            &mut cx,
            now,
            |drivers, cx| {
                Ok(poll_outputs(&writer, drivers, &mut first, cx, now, || {
                    true
                })?)
            },
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::WriteZero
        );
        let n = read_packet(reader.as_raw_fd(), &mut record).unwrap();
        assert!(n > VNET_BYTES + 40);
        let packet_len = usize::from(u16::from_be_bytes([
            record[VNET_BYTES + 2],
            record[VNET_BYTES + 3],
        ]));
        assert!(
            n < VNET_BYTES + packet_len,
            "kernel must accept only a prefix of the offered record"
        );
        assert!(packet_len <= 40 + 9_000);
        let (header, tcp_len) = wire::tcp::parse(&record[VNET_BYTES + 20..n]).unwrap();
        assert_eq!(header.seq, seq);
        let prefix = &record[VNET_BYTES + 20 + tcp_len..n];
        assert!(!prefix.is_empty() && prefix.iter().all(|&byte| byte == 0x7c));
        assert_eq!(
            read_packet(reader.as_raw_fd(), &mut record)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(scope.stats().unwrap().tx_packets, before);
        drop(flow);
        stop_driven(endpoints, owner, driver, scope, budget).await;
        assert_eq!(
            read_packet(reader.as_raw_fd(), &mut record)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    })
    .await
    .expect("a positive short write must lead directly to joined teardown");
}

#[tokio::test]
async fn standalone_write_turn_rotates_realms_and_classes_under_interruptions() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let budget = MemoryBudget::new(8 << 20);
        let (plain, plain_owner) = scope_in_budget(STANDALONE_TX_CAPS, &budget);
        let (second, second_owner) = scope_in_budget(STANDALONE_TX_CAPS, &budget);
        let (endpoints, mut owner, mut drivers) = start_driven_scopes(vec![
            (plain.clone(), plain_owner),
            (second.clone(), second_owner),
        ])
        .await;
        let now = Instant::now() + Duration::from_secs(10);
        let server = SERVER.parse().unwrap();
        let mut first_group = 0;
        for (scope, host) in [(&plain, 1), (&second, 2)] {
            let client = SocketAddr::from(([192, 0, 2, host], 41000));
            assert_eq!(
                scope.receive(&segment(client, server, 19, 2, wire::tcp::ACK), now),
                Rx::Dropped(DropReason::NoFlow)
            );
            scope
                .datagram_sender(server)
                .send_to(&[host], client)
                .await
                .unwrap();
        }
        for (first_host, first_proto) in [
            (1, wire::PROTO_TCP),
            (1, wire::PROTO_UDP),
            (2, wire::PROTO_TCP),
            (2, wire::PROTO_UDP),
        ] {
            let mut calls = 0;
            assert!(
                write_output_turn(
                    &mut drivers,
                    &mut first_group,
                    now,
                    || true,
                    |header, _, _| {
                        if calls == 0 {
                            assert_eq!((header[19], header[9]), (first_host, first_proto));
                        }
                        calls += 1;
                        Err(io::ErrorKind::Interrupted.into())
                    }
                )
                .unwrap()
            );
            assert!((BATCH * 2 - 2..=BATCH * 2).contains(&calls));
        }
        let mut calls = 0;
        let error = write_output_turn(
            &mut drivers,
            &mut first_group,
            now,
            || true,
            |_, _, tx| {
                calls += 1;
                require_complete_write(0, VNET_BYTES + tx.len)
            },
        )
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);

        endpoints.close();
        let (plane, result) = poll_fn(|cx| {
            service_turn(&mut drivers, cx, now, |_, _| Ok(false)).unwrap();
            owner.poll_join_plane(cx)
        })
        .await
        .unwrap();
        result.unwrap();
        drop((plane, endpoints, owner, drivers, plain, second));
        assert_eq!(budget.used(), 0);
    })
    .await
    .unwrap();
}
