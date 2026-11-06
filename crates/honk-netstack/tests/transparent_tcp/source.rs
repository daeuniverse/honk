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
            for (index, fragment) in fragments.iter().enumerate() {
                let (rx, source) = stack.receive_with_source(now, fragment, |source| {
                    reported.push(source);
                    true
                });
                if index + 1 == fragments.len() {
                    assert_eq!(source, Some(expected));
                    if protocol == wire::PROTO_UDP {
                        assert!(matches!(rx, Rx::TransparentOwned { .. }));
                    } else {
                        assert_eq!(rx, Rx::Consumed);
                    }
                } else {
                    assert_eq!(source, None);
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
                assert_eq!(stack.poll_accept().unwrap().client, current);
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
