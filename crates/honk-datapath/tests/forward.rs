use honk_datapath::{
    ScopeId,
    forward::{CoreForward, ForwardLease, Ingress, MarkProvenance, Prepared, Route},
};
use honk_netstack::{
    MemoryBudget,
    transit::TransitError,
    wire::{self, ParseError},
};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

fn ingress() -> Ingress {
    Ingress {
        scope: ScopeId::HOST,
        namespace: 19,
        ifindex: 3,
        attachment: 7,
        mark: MarkProvenance::BeforeSkb,
    }
}
fn route(ipv6: bool, mtu: u32) -> Route {
    Route {
        generation: 1,
        ifindex: 4,
        mtu,
        l2: honk_datapath::forward::LinkPath::untagged(4),
        next_hop: if ipv6 { "fd00::2" } else { "192.0.2.2" }.parse().unwrap(),
        preferred_source: None,
        source_mac: [2, 0, 0, 0, 0, 1],
        destination_mac: [2, 0, 0, 0, 0, 2],
    }
}
fn udp(ipv6: bool, length: usize) -> Vec<u8> {
    let (source, destination): (SocketAddr, SocketAddr) = if ipv6 {
        (
            "[fd00::1]:40000".parse().unwrap(),
            "[fd00::2]:41000".parse().unwrap(),
        )
    } else {
        (
            "192.0.2.1:40000".parse().unwrap(),
            "192.0.2.2:41000".parse().unwrap(),
        )
    };
    let mut packet = vec![0; length + 48];
    let n = wire::udp::emit_packet(&mut packet, source, destination, &vec![0x5a; length]).unwrap();
    packet.truncate(n);
    packet
}
fn seal(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let checksum = wire::checksum::checksum(&packet[..usize::from(packet[0] & 15) * 4]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn ipv6_fragment(input: &[u8], id: u32, offset: usize, length: usize, more: bool) -> Vec<u8> {
    let mut packet = input[..40].to_vec();
    packet[4..6].copy_from_slice(&((8 + length) as u16).to_be_bytes());
    packet[6] = 44;
    packet.extend_from_slice(&[input[6], 0]);
    packet.extend_from_slice(&(offset as u16 | u16::from(more)).to_be_bytes());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&input[40 + offset..40 + offset + length]);
    packet
}

#[test]
fn transit_preserves_transport_decrements_once_and_keeps_cq_owner_funded() {
    let now = Instant::now();
    for ipv6 in [false, true] {
        let budget = MemoryBudget::new(16 << 20);
        let mut core = CoreForward::new(&[ingress()], budget.clone(), 4).unwrap();
        let input = udp(ipv6, 64);
        let packet = core.receive(ingress(), now, &input).unwrap().unwrap();
        let Prepared::Forward(mut output) =
            core.prepare(packet, route(ipv6, 1500), 0, now).unwrap()
        else {
            panic!()
        };
        let mut short = [0; 8];
        assert!(output.write_next(&mut short).is_none());
        let mut bytes = [0; 1500];
        let (n, lease) = output.write_next(&mut bytes).unwrap();
        let decoded = wire::parse_ip(&bytes[..n]).unwrap();
        assert_eq!(decoded.hop_limit, 63);
        let original = wire::parse_ip(&input).unwrap();
        assert_eq!(&bytes[decoded.payload], &input[original.payload]);
        assert!(output.write_next(&mut bytes).is_none());
        core.retire(now + Duration::from_secs(121));
        drop(output);
        drop(core);
        assert!(
            budget.used() > 0,
            "CQ owner must retain packet and slow-flow charge"
        );
        drop(lease);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn mtu_df_ipv6_ptb_and_ipv4_fragmentation_keep_original_quote() {
    let now = Instant::now();
    let mut core = CoreForward::new(&[ingress()], MemoryBudget::new(16 << 20), 4).unwrap();
    let mut input = udp(false, 180);
    let packet = core.receive(ingress(), now, &input).unwrap().unwrap();
    assert!(matches!(
        core.prepare(packet, route(false, 100), 1, now).unwrap(),
        Prepared::Error {
            error: TransitError::PacketTooBig { mtu: 100 },
            ..
        }
    ));
    input[6] = 0;
    seal(&mut input);
    let packet = core.receive(ingress(), now, &input).unwrap().unwrap();
    let Prepared::Forward(mut output) = core.prepare(packet, route(false, 100), 1, now).unwrap()
    else {
        panic!()
    };
    let mut data = Vec::new();
    let mut out = [0; 100];
    while let Some((n, _lease)) = output.write_next(&mut out) {
        assert_eq!(out[8], 63);
        assert_eq!(wire::checksum::checksum(&out[..20]), 0);
        assert_eq!(
            usize::from(u16::from_be_bytes([out[6], out[7]]) & 0x1fff) * 8,
            data.len()
        );
        data.extend_from_slice(&out[20..n]);
    }
    assert_eq!(data, input[20..]);
    let input6 = udp(true, 1300);
    let packet = core.receive(ingress(), now, &input6).unwrap().unwrap();
    assert_eq!(packet.ipv6_fragment(), None);
    assert!(matches!(
        core.prepare(packet, route(true, 1280), 1, now).unwrap(),
        Prepared::Error {
            error: TransitError::PacketTooBig { mtu: 1280 },
            ..
        }
    ));
    let validated = core
        .validate_view(ingress(), now, wire::PacketView::from_slice(&input6))
        .unwrap();
    assert!(
        core.prepare_view(validated, route(true, 1280), 1, now)
            .unwrap()
            .is_none()
    );
    let mut ttl = udp(false, 12);
    ttl[8] = 1;
    seal(&mut ttl);
    let packet = core.receive(ingress(), now, &ttl).unwrap().unwrap();
    let Prepared::Error { packet, error } =
        core.prepare(packet, route(false, 1500), 1, now).unwrap()
    else {
        panic!()
    };
    assert_eq!(error, TransitError::HopLimitExceeded);
    let mut out = [0; 576];
    let source: IpAddr = "192.0.2.254".parse().unwrap();
    let n = core
        .error(now, error, source, &packet, &mut out)
        .unwrap()
        .unwrap();
    let error_ip = wire::parse_ip(&out[..n]).unwrap();
    assert_eq!(error_ip.src, source);
    assert_eq!(
        &out[error_ip.payload.start..error_ip.payload.start + 2],
        &[11, 0]
    );
    assert_eq!(&out[error_ip.payload.start + 8..n], ttl);
}

#[test]
fn bad_checksum_and_unknown_mark_never_create_forwarding_state() {
    let mut bad = ingress();
    bad.mark = MarkProvenance::Unavailable;
    assert!(CoreForward::new(&[bad], MemoryBudget::new(16 << 20), 4).is_err());
    let mut core = CoreForward::new(&[ingress()], MemoryBudget::new(16 << 20), 4).unwrap();
    let mut input = udp(true, 12);
    *input.last_mut().unwrap() ^= 1;
    let error = core
        .receive(ingress(), Instant::now(), &input)
        .err()
        .unwrap();
    assert!(matches!(
        error,
        honk_datapath::forward::ForwardError::Packet(ParseError::Checksum)
    ));
}

#[test]
fn shared_reassembly_never_terminates_transit_and_timeout_keeps_its_charge() {
    let now = Instant::now();
    let budget = MemoryBudget::new(16 << 20);
    let mut core = CoreForward::new(&[ingress()], budget.clone(), 4).unwrap();
    let input = udp(false, 24);
    let fragment = |offset: usize, length: usize, more: bool| {
        let mut packet = input[..20].to_vec();
        packet.extend_from_slice(&input[20 + offset..20 + offset + length]);
        packet[2..4].copy_from_slice(&((20 + length) as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&123u16.to_be_bytes());
        packet[6..8]
            .copy_from_slice(&((offset / 8) as u16 | if more { 0x2000 } else { 0 }).to_be_bytes());
        seal(&mut packet);
        packet
    };
    let first = fragment(0, 16, true);
    assert!(core.receive(ingress(), now, &first).unwrap().is_none());
    let packet = core
        .receive(ingress(), now, &fragment(16, 16, false))
        .unwrap()
        .unwrap();
    assert_eq!(&packet.as_ref()[20..], &input[20..]);
    assert!(matches!(
        core.prepare(packet, route(false, 1500), 0, now).unwrap(),
        Prepared::Forward(_)
    ));
    assert!(core.receive(ingress(), now, &first).unwrap().is_none());
    core.retire(now + Duration::from_secs(31));
    let (_, quote) = core.poll_expired_quote().unwrap();
    let mut out = [0; 576];
    let n = core
        .reassembly_error(
            ingress(),
            now + Duration::from_secs(31),
            "192.0.2.254".parse().unwrap(),
            &quote,
            &mut out,
        )
        .unwrap()
        .unwrap();
    assert_eq!(&out[20..22], &[11, 1]);
    assert!(n > 28);
    drop(core);
    assert!(budget.used() > 0);
    drop(quote);
    assert_eq!(budget.used(), 0);
}

#[test]
fn segmented_headers_checksum_and_reserved_tx_do_not_need_an_owned_packet() {
    let now = Instant::now();
    for ipv6 in [false, true] {
        let budget = MemoryBudget::new(16 << 20);
        let mut core = CoreForward::new(&[ingress()], budget.clone(), 4).unwrap();
        let input = udp(ipv6, 1001);
        let segments: Vec<_> = input.chunks(31).collect();
        let view = wire::PacketView::new(&segments).unwrap();
        let original = view.validate_transport().unwrap();
        let validated = core.validate_view(ingress(), now, view).unwrap();
        let mut output = core
            .prepare_view(validated, route(ipv6, 1500), 0, now)
            .unwrap()
            .unwrap();
        let lease = output.lease();
        assert!(
            lease.retained_packet().is_none(),
            "borrowed TX must not allocate a staging Packet"
        );
        let mut tiny = [0; 3];
        assert!(
            output
                .write_next_segments(&mut [&mut tiny], &[0; 14])
                .is_none()
        );
        let mut a = [0; 5];
        let mut b = [0; 17];
        let mut c = [0; 1500];
        let n = output
            .write_next_segments(&mut [&mut a, &mut b, &mut c], &[0x55; 14])
            .unwrap();
        assert!(output.is_complete());
        let frame: Vec<_> = a.into_iter().chain(b).chain(c).take(n).collect();
        assert_eq!(&frame[..14], &[0x55; 14]);
        let forwarded = wire::PacketView::from_slice(&frame[14..])
            .validate_transport()
            .unwrap();
        assert_eq!(forwarded.hop_limit, 63);
        assert_eq!(
            &frame[14 + forwarded.payload.start..],
            &input[original.payload]
        );
        drop(output);
        drop(core);
        assert!(budget.used() > 0);
        drop(lease);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn segmented_endpoint_validation_preserves_long_extension_and_flow_label_semantics() {
    let original = udp(true, 16);
    let mut packet = original[..40].to_vec();
    packet[6] = 0;
    packet[1] |= 1;
    packet.extend_from_slice(&[17, 255]);
    packet.resize(40 + 2048, 0);
    packet.extend_from_slice(&original[40..]);
    let payload = (packet.len() - 40) as u16;
    packet[4..6].copy_from_slice(&payload.to_be_bytes());
    let segments: Vec<_> = packet.chunks(47).collect();
    let view = wire::PacketView::new(&segments).unwrap();
    assert_eq!(view.validate_transport().unwrap().payload.start, 40 + 2048);
    let now = Instant::now();
    let mut core = CoreForward::new(&[ingress()], MemoryBudget::new(16 << 20), 4).unwrap();
    let validated = core.validate_view(ingress(), now, view).unwrap();
    assert!(validated.validate_core().is_err());
    assert!(
        core.prepare_view(validated, route(true, 9000), 0, now)
            .is_err()
    );
    let packet = core
        .receive_segments(ingress(), now, &segments)
        .unwrap()
        .unwrap();
    assert_eq!(packet.query().ports, Some((40000, 41000)));
    assert!(packet.validate_core().is_err());
}

#[test]
fn failed_translation_cannot_submit_and_tcp_reset_never_gets_a_refusal() {
    let now = Instant::now();
    let mut core = CoreForward::new(&[ingress()], MemoryBudget::new(16 << 20), 4).unwrap();
    let mut packet = core
        .receive(ingress(), now, &udp(false, 16))
        .unwrap()
        .unwrap();
    assert!(
        packet
            .rewrite(|bytes| {
                *bytes.last_mut().unwrap() ^= 1;
                Ok(())
            })
            .is_err()
    );
    assert!(core.prepare(packet, route(false, 1500), 0, now).is_err());
    let source: IpAddr = "192.0.2.1".parse().unwrap();
    let destination: IpAddr = "192.0.2.2".parse().unwrap();
    let mut rst = [0; 40];
    wire::emit_ip_header(&mut rst, source, destination, 6, 20).unwrap();
    rst[20..22].copy_from_slice(&40000u16.to_be_bytes());
    rst[22..24].copy_from_slice(&41000u16.to_be_bytes());
    rst[32] = 0x50;
    rst[33] = 4;
    let mut checksum = wire::checksum::Checksum::pseudo(source, destination, 6, 20);
    checksum.add(&rst[20..]);
    rst[36..38].copy_from_slice(&checksum.finish().to_be_bytes());
    let packet = core.receive(ingress(), now, &rst).unwrap().unwrap();
    assert!(
        core.error(
            now,
            TransitError::AdminProhibited,
            "192.0.2.254".parse().unwrap(),
            &packet,
            &mut [0; 576]
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn one_owner_keeps_equal_tuples_in_distinct_logical_ingress_realms() {
    let now = Instant::now();
    let first = ingress();
    let second = Ingress {
        ifindex: 9,
        attachment: 11,
        ..first
    };
    let mut core = CoreForward::new(&[first, second], MemoryBudget::new(16 << 20), 4).unwrap();
    let input = udp(false, 32);
    let mut outputs = Vec::new();
    for identity in [first, second] {
        let packet = core.receive(identity, now, &input).unwrap().unwrap();
        let Prepared::Forward(output) = core.prepare(packet, route(false, 1500), 0, now).unwrap()
        else {
            panic!()
        };
        assert_eq!(output.lease().ingress(), identity);
        outputs.push(output);
    }
    let wrong = Ingress {
        namespace: first.namespace + 1,
        ..first
    };
    assert!(core.receive(wrong, now, &input).is_err());
    let replaced = Ingress {
        attachment: first.attachment + 1,
        ..first
    };
    assert!(core.receive(replaced, now, &input).is_err());
    assert_eq!(outputs.len(), 2);
}

#[test]
fn retained_core_execution_covers_reverse_and_class_changes_until_output_return() {
    let now = Instant::now();
    let first = ingress();
    let second = Ingress {
        ifindex: 4,
        attachment: 12,
        ..first
    };
    let mut core = CoreForward::new(&[first, second], MemoryBudget::new(16 << 20), 1).unwrap();
    let mut bytes = [0; 64];
    let tcp = wire::tcp::Header {
        src_port: 40000,
        dst_port: 443,
        seq: 10,
        ack: 0,
        flags: wire::tcp::SYN,
        window: 4096,
        urgent: 0,
        options: Default::default(),
    };
    let length = wire::tcp::emit_packet(
        &mut bytes,
        "192.0.2.1".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        &tcp,
        [&[], &[]],
    )
    .unwrap();
    let packet = core.receive(first, now, &bytes[..length]).unwrap().unwrap();
    let mut original = packet.query();
    assert!(!core.retains(original, now));
    let Prepared::Forward(output) = core.prepare(packet, route(false, 1500), 1, now).unwrap()
    else {
        panic!()
    };
    let lease = output.lease();
    original.traffic_class = 0xb9;
    assert!(core.retains(original, now));
    let reverse = honk_datapath::forward::RouteQuery {
        ingress: second,
        source: original.destination,
        destination: original.source,
        ports: original
            .ports
            .map(|(source, destination)| (destination, source)),
        ..original
    };
    assert!(core.retains(reverse, now));
    assert!(!core.retains(
        honk_datapath::forward::RouteQuery {
            ingress: first,
            ..reverse
        },
        now
    ));
    assert!(!core.retains(
        honk_datapath::forward::RouteQuery {
            ingress: Ingress {
                attachment: 13,
                ..second
            },
            ..reverse
        },
        now
    ));
    drop(output);
    core.retire(now + Duration::from_secs(121));
    assert!(core.retains(reverse, now + Duration::from_secs(121)));
    drop(lease);
    core.retire(now + Duration::from_secs(121));
    assert!(core.retains(original, now + Duration::from_secs(121)));
    assert!(
        core.retains(reverse, now + Duration::from_secs(121)),
        "idle TCP must not be reclassified into Endpoint"
    );
    core.retire(now + Duration::from_secs(7439));
    assert!(core.retains(reverse, now + Duration::from_secs(7439)));
    core.retire(now + Duration::from_secs(7440));
    assert!(!core.retains(original, now + Duration::from_secs(7440)));
    assert!(!core.retains(reverse, now + Duration::from_secs(7440)));
}

#[test]
fn expired_cached_and_owned_claims_get_new_owners_unless_output_is_still_held() {
    let now = Instant::now();
    for ipv6 in [false, true] {
        for tcp in [false, true] {
            let input = if tcp {
                let mut bytes = vec![0; 80];
                let source = if ipv6 { "fd00::1" } else { "192.0.2.1" }.parse().unwrap();
                let destination = if ipv6 { "fd00::2" } else { "192.0.2.2" }.parse().unwrap();
                let length = wire::tcp::emit_packet(
                    &mut bytes,
                    source,
                    destination,
                    &wire::tcp::Header {
                        src_port: 40000,
                        dst_port: 443,
                        seq: 10,
                        ack: 0,
                        flags: wire::tcp::SYN,
                        window: 4096,
                        urgent: 0,
                        options: Default::default(),
                    },
                    [&[], &[]],
                )
                .unwrap();
                bytes.truncate(length);
                bytes
            } else {
                udp(ipv6, 32)
            };
            let ttl = Duration::from_secs(if tcp { 7440 } else { 120 });
            let expired = now + ttl;
            for cached in [false, true] {
                for held in [false, true] {
                    let mut core =
                        CoreForward::new(&[ingress()], MemoryBudget::new(16 << 20), 2).unwrap();
                    let query = core
                        .validate_view(ingress(), now, wire::PacketView::from_slice(&input))
                        .unwrap()
                        .query();
                    let publish = |core: &mut CoreForward,
                                   at: Instant,
                                   generation: u64|
                     -> ForwardLease {
                        let mut bytes = [0; 1500];
                        if cached {
                            let validated = core
                                .validate_view(ingress(), at, wire::PacketView::from_slice(&input))
                                .unwrap();
                            let mut output = core
                                .prepare_view(validated, route(ipv6, 1500), generation, at)
                                .unwrap()
                                .unwrap();
                            assert_eq!(
                                output.write_next_segments(&mut [&mut bytes], &[]),
                                Some(input.len())
                            );
                            output.lease()
                        } else {
                            let packet = core.receive(ingress(), at, &input).unwrap().unwrap();
                            let Prepared::Forward(mut output) = core
                                .prepare(packet, route(ipv6, 1500), generation, at)
                                .unwrap()
                            else {
                                panic!("valid packet must produce Core output");
                            };
                            let (length, lease) = output.write_next(&mut bytes).unwrap();
                            assert_eq!(length, input.len());
                            lease
                        }
                    };
                    let mut old_output = Some(publish(&mut core, now, 1));
                    if !held {
                        drop(old_output.take());
                    }
                    assert!(core.retains(query, expired - Duration::from_nanos(1)));
                    assert_eq!(core.retains(query, expired), held);
                    let new_output = publish(&mut core, expired, 2);
                    assert_eq!(new_output.policy_generation(), if held { 1 } else { 2 });
                    assert_eq!(new_output.ingress(), ingress());
                    drop(old_output);
                    drop(new_output);
                    assert!(core.retains(query, expired + ttl - Duration::from_nanos(1)));
                    assert!(!core.retains(query, expired + ttl));
                }
            }
        }
    }
}

#[test]
fn out_of_order_ipv6_reassembly_restores_original_fragments_and_cq_charge() {
    let now = Instant::now();
    let id = 0x89ab_cdef;
    let payload: Vec<_> = (0..2048).map(|byte| (byte % 251) as u8).collect();
    let mut input = vec![0; payload.len() + 48];
    let length = wire::udp::emit_packet(
        &mut input,
        "[fd00::1]:40000".parse().unwrap(),
        "[fd00::2]:41000".parse().unwrap(),
        &payload,
    )
    .unwrap();
    input.truncate(length);
    for mtu in [1280, 9000] {
        let budget = MemoryBudget::new(16 << 20);
        let mut core = CoreForward::new(&[ingress()], budget.clone(), 4).unwrap();
        // The largest received fragment is neither fragment zero nor the last arrival.
        let mut middle = ipv6_fragment(&input, id, 616, 1232, true);
        middle.extend_from_slice(&[0xa5; 32]);
        assert!(core.receive(ingress(), now, &middle).unwrap().is_none());
        assert!(
            core.receive(ingress(), now, &ipv6_fragment(&input, id, 1848, 208, false))
                .unwrap()
                .is_none()
        );
        let packet = core
            .receive(ingress(), now, &ipv6_fragment(&input, id, 0, 616, true))
            .unwrap()
            .unwrap();
        assert_eq!(
            packet.ipv6_fragment(),
            Some(honk_netstack::transit::Ipv6Fragment { id, max_size: 1280 })
        );
        assert_eq!(packet.as_ref(), input);
        let Prepared::Forward(mut output) = core.prepare(packet, route(true, mtu), 1, now).unwrap()
        else {
            panic!("fitting original fragments must not produce datagram PTB")
        };
        let mut leases = Vec::new();
        let mut transport = Vec::new();
        for (offset, length, more) in [(0, 1232, true), (1232, 824, false)] {
            assert_eq!(output.next_len(), Some(48 + length));
            let mut short = vec![0; 47 + length];
            assert!(output.write_next(&mut short).is_none());
            assert_eq!(output.next_len(), Some(48 + length));
            let mut bytes = [0; 1280];
            let (written, lease) = output.write_next(&mut bytes).unwrap();
            let mut expected = ipv6_fragment(&input, id, offset, length, more);
            expected[7] -= 1;
            assert_eq!(&bytes[..written], expected);
            assert_eq!(u32::from_be_bytes(bytes[44..48].try_into().unwrap()), id);
            assert_eq!(
                u16::from_be_bytes(bytes[42..44].try_into().unwrap()),
                offset as u16 | u16::from(more)
            );
            assert_eq!(bytes[40], 17);
            assert_eq!(bytes[7], 63);
            assert_eq!(lease.retained_packet().unwrap().as_ref(), input);
            transport.extend_from_slice(&bytes[48..written]);
            leases.push(lease);
        }
        assert!(output.is_complete());
        assert_eq!(output.next_len(), None);
        assert_eq!(transport, input[40..]);
        assert_eq!(&transport[6..8], &input[46..48]);
        let mut restored = input[..40].to_vec();
        restored.extend_from_slice(&transport);
        wire::PacketView::from_slice(&restored)
            .validate_transport()
            .unwrap();
        drop(output);
        drop(core);
        let held = budget.used();
        assert!(held > input.len());
        drop(leases.pop());
        assert_eq!(
            budget.used(),
            held,
            "every fragment retains the original charge to CQ"
        );
        drop(leases);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn oversized_original_ipv6_fragment_produces_ptb_without_losing_its_charge() {
    let now = Instant::now();
    let budget = MemoryBudget::new(16 << 20);
    let mut core = CoreForward::new(&[ingress()], budget.clone(), 4).unwrap();
    let input = udp(true, 2048);
    let id = 0x1234_abcd;
    assert!(
        core.receive(ingress(), now, &ipv6_fragment(&input, id, 616, 1240, true))
            .unwrap()
            .is_none()
    );
    assert!(
        core.receive(ingress(), now, &ipv6_fragment(&input, id, 1856, 200, false))
            .unwrap()
            .is_none()
    );
    let packet = core
        .receive(ingress(), now, &ipv6_fragment(&input, id, 0, 616, true))
        .unwrap()
        .unwrap();
    assert_eq!(packet.ipv6_fragment().unwrap().max_size, 1288);
    let Prepared::Error { packet, error } =
        core.prepare(packet, route(true, 1280), 1, now).unwrap()
    else {
        panic!("an oversized original fragment requires PTB")
    };
    assert_eq!(error, TransitError::PacketTooBig { mtu: 1280 });
    assert_eq!(packet.as_ref(), input);
    let mut bytes = [0; 1280];
    let written = core
        .error(now, error, "fd00::fe".parse().unwrap(), &packet, &mut bytes)
        .unwrap()
        .unwrap();
    assert!(written <= 1280);
    assert_eq!(&bytes[40..42], &[2, 0]);
    assert_eq!(&bytes[44..48], &1280u32.to_be_bytes());
    drop(core);
    assert!(budget.used() > input.len());
    drop(packet);
    assert_eq!(budget.used(), 0);
}

#[test]
fn untrusted_tcp_close_cannot_shorten_cached_or_owned_execution_retention() {
    let now = Instant::now();
    let first = ingress();
    let second = Ingress {
        ifindex: 4,
        attachment: 12,
        ..first
    };
    for (close, cached) in [wire::tcp::FIN | wire::tcp::ACK, wire::tcp::RST]
        .into_iter()
        .flat_map(|close| [(close, false), (close, true)])
    {
        let mut core = CoreForward::new(&[first, second], MemoryBudget::new(16 << 20), 2).unwrap();
        let mut bytes = [0; 64];
        let mut header = wire::tcp::Header {
            src_port: 40000,
            dst_port: 443,
            seq: 10,
            ack: 0,
            flags: wire::tcp::SYN,
            window: 4096,
            urgent: 0,
            options: Default::default(),
        };
        let source = "192.0.2.1".parse().unwrap();
        let destination = "192.0.2.2".parse().unwrap();
        let len =
            wire::tcp::emit_packet(&mut bytes, source, destination, &header, [&[], &[]]).unwrap();
        let packet = core.receive(first, now, &bytes[..len]).unwrap().unwrap();
        let original = packet.query();
        drop(core.prepare(packet, route(false, 1500), 1, now).unwrap());
        header.src_port = 443;
        header.dst_port = 40000;
        header.flags = close;
        let len =
            wire::tcp::emit_packet(&mut bytes, destination, source, &header, [&[], &[]]).unwrap();
        let validated = core
            .validate_view(second, now, wire::PacketView::from_slice(&bytes[..len]))
            .unwrap();
        let reverse = validated.query();
        let reply_route = Route {
            ifindex: first.ifindex,
            l2: honk_datapath::forward::LinkPath::untagged(first.ifindex),
            next_hop: source,
            ..route(false, 1500)
        };
        if cached {
            drop(
                core.prepare_view(validated, reply_route, 1, now)
                    .unwrap()
                    .unwrap(),
            );
        } else {
            let packet = core.receive(second, now, &bytes[..len]).unwrap().unwrap();
            drop(core.prepare(packet, reply_route, 1, now).unwrap());
        }
        core.retire(now + Duration::from_secs(60));
        assert!(core.retains(original, now + Duration::from_secs(60)));
        assert!(core.retains(reverse, now + Duration::from_secs(60)));
        header.dst_port += 1;
        header.flags = wire::tcp::SYN;
        let len =
            wire::tcp::emit_packet(&mut bytes, destination, source, &header, [&[], &[]]).unwrap();
        let packet = core.receive(second, now, &bytes[..len]).unwrap().unwrap();
        assert!(matches!(
            core.prepare(packet, reply_route, 1, now),
            Err(honk_datapath::forward::ForwardError::Capacity)
        ));
        let expired = now + Duration::from_secs(7440);
        core.retire(expired);
        assert!(!core.retains(original, expired));
        assert!(!core.retains(reverse, expired));
        let packet = core
            .receive(second, expired, &bytes[..len])
            .unwrap()
            .unwrap();
        assert!(matches!(
            core.prepare(packet, reply_route, 2, expired).unwrap(),
            Prepared::Forward(_)
        ));
    }
}

#[test]
fn fragment_obligations_follow_live_reassembly_and_queued_quotes_not_tombstones() {
    let now = Instant::now();
    let mut core = CoreForward::new(&[ingress()], MemoryBudget::new(16 << 20), 2).unwrap();
    let input = udp(true, 32);
    let first = ipv6_fragment(&input, 1, 0, 16, true);
    assert!(core.receive(ingress(), now, &first).unwrap().is_none());
    let pending = core.fragment_obligations().next().unwrap();
    assert_eq!(pending.ingress, ingress());
    assert_eq!(pending.source, "fd00::1".parse::<IpAddr>().unwrap());
    assert_eq!(pending.destination, "fd00::2".parse::<IpAddr>().unwrap());
    assert_eq!(pending.protocol, wire::PROTO_UDP);
    let tail = ipv6_fragment(&input, 1, 16, 24, false);
    assert!(
        core.receive(ingress(), now, &tail)
            .unwrap()
            .unwrap()
            .is_reassembled()
    );
    assert!(core.fragment_obligations().next().is_none());
    assert!(core.receive(ingress(), now, &first).unwrap().is_none());
    assert!(core.receive(ingress(), now, &first).is_err());
    assert!(!core.fragments_quiescent());
    assert!(core.fragment_obligations().next().is_none());
    let first = ipv6_fragment(&input, 2, 0, 16, true);
    assert!(core.receive(ingress(), now, &first).unwrap().is_none());
    core.retire(now + Duration::from_secs(30));
    assert_eq!(core.fragment_obligations().collect::<Vec<_>>(), [pending]);
    assert!(core.poll_expired_quote().is_some());
    assert!(core.fragment_obligations().next().is_none());
}

#[test]
fn unbound_native_echo_remaps_restore_full_quotes_in_owned_and_borrowed_output() {
    use honk_datapath::firewall::{Admission, DestinationNat, Facts, Firewall, SourceNat};

    let echo = |kind: u8, destination: IpAddr, identifier: u16| {
        let mut bytes = vec![0; 36];
        wire::emit_ip_header(
            &mut bytes,
            "192.0.2.1".parse().unwrap(),
            destination,
            wire::PROTO_ICMP,
            16,
        )
        .unwrap();
        bytes[4..8].fill(0);
        bytes[20] = kind;
        bytes[24..26].copy_from_slice(&identifier.to_be_bytes());
        bytes[26..28].copy_from_slice(&0x55aau16.to_be_bytes());
        bytes[28..].copy_from_slice(b"not-zero");
        let checksum = wire::checksum::checksum(&bytes[20..]);
        bytes[22..24].copy_from_slice(&checksum.to_be_bytes());
        seal(&mut bytes);
        bytes
    };
    for (borrowed, kind) in [false, true]
        .into_iter()
        .flat_map(|borrowed| [(borrowed, 0), (borrowed, 8)])
    {
        let now = Instant::now();
        let first = ingress();
        let reply = Ingress {
            ifindex: 4,
            ..first
        };
        let budget = MemoryBudget::new(16 << 20);
        let mut core = CoreForward::new(&[first, reply], budget.clone(), 2).unwrap();
        let mut table = Firewall::new_history(budget.clone(), 2, 1).unwrap();
        let mut managed = echo(8, "198.51.100.99".parse().unwrap(), 0x1122);
        let managed_facts = Facts::parse(&managed).unwrap();
        let grant = table
            .admit(Admission {
                ingress: first,
                reply_ingress: reply,
                facts: &managed_facts,
                dnat: Some(DestinationNat {
                    address: "192.0.2.2".parse().unwrap(),
                    port: None,
                }),
                snat: SourceNat::None,
                egress: None,
                received_at: now,
                now,
            })
            .unwrap();
        grant.rewrite(&mut managed, false).unwrap();
        let original_id = u16::from_be_bytes([managed[4], managed[5]]);
        let mut native_input = echo(kind, "192.0.2.2".parse().unwrap(), 0x5a3c);
        native_input[4..6].copy_from_slice(&original_id.to_be_bytes());
        seal(&mut native_input);
        let mut output = [0; 1500];
        let (len, cq) = if borrowed {
            let segments = [
                &native_input[..25],
                &native_input[25..27],
                &native_input[27..],
            ];
            let input = core
                .validate_view(first, now, wire::PacketView::new(&segments).unwrap())
                .unwrap();
            assert!(
                input.query().ports.is_none(),
                "echo IDs must not become routing ports"
            );
            let mut forward = core
                .prepare_view(input, route(false, 1500), 1, now)
                .unwrap()
                .unwrap();
            let (tuple, id) = forward.native_identity().unwrap();
            forward.bind_native(table.observe_plain(first, reply, tuple, id, now).unwrap());
            let len = forward
                .write_next_segments(&mut [&mut output], &[])
                .unwrap();
            (len, forward.lease())
        } else {
            let mut packet = core.receive(first, now, &native_input).unwrap().unwrap();
            assert!(
                packet.query().ports.is_none(),
                "echo IDs must not become routing ports"
            );
            let (tuple, id) = packet.native_identity().unwrap();
            packet.bind_native(table.observe_plain(first, reply, tuple, id, now).unwrap());
            let Prepared::Forward(mut forward) =
                core.prepare(packet, route(false, 1500), 1, now).unwrap()
            else {
                panic!("valid native echo must remain routed traffic");
            };
            forward.write_next(&mut output).unwrap()
        };
        wire::PacketView::from_slice(&output[..len])
            .validate_transport()
            .unwrap();
        assert_ne!(u16::from_be_bytes([output[4], output[5]]), original_id);
        assert_eq!(&output[24..26], &0x5a3cu16.to_be_bytes());
        assert!(
            table
                .lookup(first, &Facts::parse(&native_input).unwrap(), now)
                .unwrap()
                .is_none()
        );
        let mut error = vec![0; 28 + len];
        wire::emit_ip_header(
            &mut error,
            "192.0.2.254".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            wire::PROTO_ICMP,
            8 + len,
        )
        .unwrap();
        error[20] = 3;
        error[21] = 1;
        error[28..].copy_from_slice(&output[..len]);
        let checksum = wire::checksum::checksum(&error[20..]);
        error[22..24].copy_from_slice(&checksum.to_be_bytes());
        let facts = Facts::parse(&error).unwrap();
        assert!(table.retain_native_quote(first, &facts).is_none());
        let quote = table
            .retain_native_quote(reply, &facts)
            .expect("full nonzero-identifier echo quote must find its unbound remap");
        table.revoke(2);
        drop(grant);
        drop(cq);
        table.expire(now);
        table.expire(now + Duration::from_secs(241));
        quote.rewrite(&mut error).unwrap();
        wire::PacketView::from_slice(&error)
            .validate_transport()
            .unwrap();
        let restored = Facts::parse(&error[28..]).unwrap();
        assert_eq!(restored.tuple.source_port, 0x5a3c);
        assert_eq!(restored.tuple.destination_port, 0x5a3c);
        assert_eq!(u16::from_be_bytes([error[32], error[33]]), original_id);
        output[4..6].copy_from_slice(&original_id.to_be_bytes());
        seal(&mut output[..len]);
        assert_eq!(&error[28..], &output[..len]);
        drop(core);
        drop(table);
        assert!(budget.used() > 0, "the exported quote owner remains funded");
        drop(quote);
        assert_eq!(budget.used(), 0);
    }
}
