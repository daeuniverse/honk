use super::*;
#[test]
fn hairpin_aliases_checksum_and_reply_ownership() {
    let now = Instant::now();
    let mut table = table();
    let original = tuple("10.0.0.2:1234", "198.51.100.1:8080", 17);
    let mut bytes = udp(original);
    let facts = Facts::parse(&bytes).unwrap();
    let dnat = DestinationNat {
        address: "10.0.0.8".parse().unwrap(),
        port: Some(80),
    };
    let binding = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(1),
            facts: &facts,
            dnat: Some(dnat),
            snat: snat(),
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    binding.rewrite(&mut bytes, true).unwrap();
    assert_eq!(
        Facts::parse(&bytes).unwrap().tuple.destination,
        dnat.address
    );
    binding.rewrite(&mut bytes, false).unwrap();
    assert_eq!(Facts::parse(&bytes).unwrap().tuple, binding.after_route());
    let mut reply = udp(binding.after_route().reverse());
    let facts = Facts::parse(&reply).unwrap();
    assert!(matches!(
        table.lookup(ingress(2), &facts, now),
        Err(FirewallError::Denied)
    ));
    let reverse = table.lookup(ingress(1), &facts, now).unwrap().unwrap();
    reverse.rewrite(&mut reply, true).unwrap();
    reverse.rewrite(&mut reply, false).unwrap();
    assert_eq!(Facts::parse(&reply).unwrap().tuple, original.reverse());
    let stranger = Facts::parse(&udp(Tuple {
        source: "10.0.0.9".parse().unwrap(),
        ..binding.after_route().reverse()
    }))
    .unwrap();
    assert!(table.lookup(ingress(1), &stranger, now).unwrap().is_none());
}

#[test]
fn logical_ingress_aliases_share_one_public_port_pool() {
    let now = Instant::now();
    let mut table = table();
    let facts = Facts::parse(&udp(tuple("10.0.0.2:1234", "192.0.2.9:53", 17))).unwrap();
    let action = SourceNat::Snat {
        address: "198.51.100.1".parse().unwrap(),
        ports: Some(PortPool {
            first: 40000,
            last: 40001,
        }),
    };
    let first = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &facts,
            dnat: None,
            snat: action,
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    assert!(table.lookup(ingress(3), &facts, now).unwrap().is_none());
    let second = table
        .admit(Admission {
            ingress: ingress(3),
            reply_ingress: ingress(2),
            facts: &facts,
            dnat: None,
            snat: action,
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    assert_ne!(
        first.after_route().source_port,
        second.after_route().source_port
    );
    for (lease, expected_ingress) in [(first, ingress(1)), (second, ingress(3))] {
        let reply = Facts::parse(&udp(lease.after_route().reverse())).unwrap();
        let binding = table.lookup(ingress(2), &reply, now).unwrap().unwrap();
        assert_eq!(binding.egress_ingress(), expected_ingress);
        assert!(matches!(
            table.lookup(ingress(2), &reply, now - Duration::from_millis(1)),
            Err(FirewallError::Denied)
        ));
    }
}

#[test]
fn masquerade_removal_and_ipv6_firewall_without_translation() {
    let now = Instant::now();
    let mut table = table();
    let facts = Facts::parse(&udp(tuple("10.0.0.2:1000", "192.0.2.9:53", 17))).unwrap();
    let action = SourceNat::Masquerade {
        ports: PortPool {
            first: 45000,
            last: 45000,
        },
    };
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &facts,
            dnat: None,
            snat: action,
            egress: None,
            received_at: now,
            now
        }),
        Err(FirewallError::AddressUnavailable)
    ));
    let address = EgressAddress {
        ifindex: 2,
        address: "198.51.100.2".parse().unwrap(),
        generation: 1,
    };
    let lease = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &facts,
            dnat: None,
            snat: action,
            egress: Some(address),
            received_at: now,
            now,
        })
        .unwrap();
    table.invalidate_address_generation(1);
    assert!(lease.is_current(1));
    table.invalidate_address_generation(2);
    assert!(!lease.is_current(1));
    table.invalidate_address(2, address.address);
    assert!(!lease.is_current(1));
    let v6 = tuple("[2001:db8::1]:2000", "[2001:db8::2]:53", 17);
    let facts = Facts::parse(&udp(v6)).unwrap();
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &facts,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now
        }),
        Err(FirewallError::Unsupported)
    ));
    let lease = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &facts,
            dnat: None,
            snat: SourceNat::None,
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    let reverse = Facts::parse(&udp(v6.reverse())).unwrap();
    assert!(table.lookup(ingress(2), &reverse, now).unwrap().is_some());
    assert_eq!(lease.after_route(), v6);
}

#[test]
fn truncated_icmp_quote_and_udp_zero_checksum_are_repaired_safely() {
    let now = Instant::now();
    let mut table = table();
    let original = tuple("10.0.0.2:1000", "192.0.2.9:53", 17);
    let mut bytes = udp(original);
    bytes[26..28].fill(0);
    let facts = Facts::parse(&bytes).unwrap();
    let lease = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &facts,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    lease.rewrite(&mut bytes, false).unwrap();
    assert_eq!(&bytes[26..28], &[0, 0]);
    let mut error = vec![0; 20 + 8 + 28];
    wire::emit_ip_header(
        &mut error,
        "192.0.2.1".parse().unwrap(),
        lease.after_route().source,
        wire::PROTO_ICMP,
        36,
    )
    .unwrap();
    error[20] = 3;
    error[21] = 1;
    error[28..].copy_from_slice(&bytes[..28]);
    let checksum = wire::checksum::checksum(&error[20..]);
    error[22..24].copy_from_slice(&checksum.to_be_bytes());
    let related = table
        .lookup(ingress(2), &Facts::parse(&error).unwrap(), now)
        .unwrap()
        .unwrap();
    related.rewrite(&mut error, true).unwrap();
    assert_eq!(wire::parse_ip(&error).unwrap().dst, original.source);
    assert_eq!(quoted_tuple(&error[28..]).unwrap(), original);
    assert_eq!(wire::checksum::checksum(&error[20..]), 0);
    assert_eq!(&error[54..56], &[0, 0]);
    assert!(quoted_tuple(&error[28..55]).is_err());
    let tcp_original = tuple("10.0.0.3:2000", "192.0.2.9:443", 6);
    let mut tcp_bytes = tcp_packet(tcp_original, tcp::SYN, 10, 0);
    let tcp_binding = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &Facts::parse(&tcp_bytes).unwrap(),
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    tcp_binding.rewrite(&mut tcp_bytes, false).unwrap();
    wire::emit_ip_header(
        &mut error,
        "192.0.2.1".parse().unwrap(),
        tcp_binding.after_route().source,
        wire::PROTO_ICMP,
        36,
    )
    .unwrap();
    error[22..24].fill(0);
    error[28..].copy_from_slice(&tcp_bytes[..28]);
    let checksum = wire::checksum::checksum(&error[20..]);
    error[22..24].copy_from_slice(&checksum.to_be_bytes());
    let related = table
        .lookup(ingress(2), &Facts::parse(&error).unwrap(), now)
        .unwrap()
        .unwrap();
    related.rewrite(&mut error, false).unwrap();
    assert_eq!(quoted_tuple(&error[28..]).unwrap(), tcp_original);
    assert_eq!(wire::checksum::checksum(&error[20..]), 0);
    let mut fragment = udp(original);
    fragment[6] = 0x20;
    fragment[10..12].fill(0);
    let checksum = wire::checksum::checksum(&fragment[..20]);
    fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
    assert!(Facts::parse(&fragment).is_err());
}

#[test]
fn nat_rejects_nonunicast_addresses_before_publishing_bindings() {
    let now = Instant::now();
    let original = tuple("10.0.0.2:1234", "192.0.2.9:53", 17);
    let facts = Facts::parse(&udp(original)).unwrap();
    for address in ["0.1.2.3", "0.255.255.255", "240.0.0.1", "255.0.0.1"] {
        let address = address.parse().unwrap();
        let mut table = table();
        let dnat = DestinationNat {
            address,
            port: None,
        };
        assert!(matches!(
            destination_tuple(original, Some(dnat)),
            Err(FirewallError::Unsupported)
        ));
        assert!(matches!(
            table.admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &facts,
                dnat: Some(dnat),
                snat: SourceNat::None,
                egress: None,
                received_at: now,
                now
            }),
            Err(FirewallError::Unsupported)
        ));
        let snat = SourceNat::Snat {
            address,
            ports: Some(PortPool {
                first: 40000,
                last: 40001,
            }),
        };
        assert!(matches!(
            table.admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &facts,
                dnat: None,
                snat,
                egress: None,
                received_at: now,
                now
            }),
            Err(FirewallError::AddressUnavailable)
        ));
        let egress = EgressAddress {
            ifindex: 2,
            address,
            generation: 1,
        };
        let masquerade = SourceNat::Masquerade {
            ports: PortPool {
                first: 40000,
                last: 40001,
            },
        };
        assert!(matches!(
            table.admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &facts,
                dnat: None,
                snat: masquerade,
                egress: Some(egress),
                received_at: now,
                now
            }),
            Err(FirewallError::AddressUnavailable)
        ));
        assert!(table.is_empty());
        assert!(table.lookup(ingress(1), &facts, now).unwrap().is_none());
    }
}

#[test]
fn hairpin_allocator_skips_candidate_self_alias_and_restores_reply() {
    let now = Instant::now();
    let original = tuple("10.0.0.2:1234", "198.51.100.1:8080", 17);
    let dnat = DestinationNat {
        address: "10.0.0.2".parse().unwrap(),
        port: Some(1234),
    };
    let snat = SourceNat::Snat {
        address: "198.51.100.1".parse().unwrap(),
        ports: Some(PortPool {
            first: 8080,
            last: 8081,
        }),
    };
    for reply_ingress in [ingress(1), ingress(2)] {
        let mut table = table();
        let mut request = udp(original);
        let binding = table
            .admit(Admission {
                ingress: ingress(1),
                reply_ingress,
                facts: &Facts::parse(&request).unwrap(),
                dnat: Some(dnat),
                snat,
                egress: None,
                received_at: now,
                now,
            })
            .unwrap();
        assert_eq!(binding.after_route().source_port, 8081);
        binding.rewrite(&mut request, false).unwrap();
        assert_eq!(Facts::parse(&request).unwrap().tuple, binding.after_route());
        let mut response = udp(binding.after_route().reverse());
        let facts = Facts::parse(&response).unwrap();
        assert!(matches!(
            table.lookup(ingress(3), &facts, now),
            Err(FirewallError::Denied)
        ));
        let reply = table.lookup(reply_ingress, &facts, now).unwrap().unwrap();
        assert_eq!(reply.egress_ingress(), ingress(1));
        reply.rewrite(&mut response, false).unwrap();
        assert_eq!(Facts::parse(&response).unwrap().tuple, original.reverse());
    }
    let mut table = table();
    let only_alias = SourceNat::Snat {
        address: "198.51.100.1".parse().unwrap(),
        ports: Some(PortPool {
            first: 8080,
            last: 8080,
        }),
    };
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(1),
            facts: &Facts::parse(&udp(original)).unwrap(),
            dnat: Some(dnat),
            snat: only_alias,
            egress: None,
            received_at: now,
            now
        }),
        Err(FirewallError::Exhausted)
    ));
    assert!(table.is_empty());
}

#[test]
fn compact_related_lease_derives_both_directions_and_preserves_error_source() {
    let now = Instant::now();
    for ipv6 in [false, true] {
        let mut table = table();
        let original = if ipv6 {
            tuple("[2001:db8::2]:1234", "[2001:db8::9]:8080", wire::PROTO_UDP)
        } else {
            tuple("10.0.0.2:1234", "198.51.100.9:8080", wire::PROTO_UDP)
        };
        let facts = Facts::parse(&udp(original)).unwrap();
        let dnat = (!ipv6).then(|| DestinationNat {
            address: "10.0.1.8".parse().unwrap(),
            port: Some(80),
        });
        let lease = table
            .admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &facts,
                dnat,
                snat: if ipv6 { SourceNat::None } else { snat() },
                egress: None,
                received_at: now,
                now,
            })
            .unwrap();
        for quoted_reply in [false, true] {
            let (quote, restored, input, output) = if quoted_reply {
                (
                    original.reverse(),
                    lease.after_route().reverse(),
                    ingress(1),
                    ingress(2),
                )
            } else {
                (lease.after_route(), original, ingress(2), ingress(1))
            };
            for router_error in [false, true] {
                let source = if router_error {
                    if ipv6 {
                        "2001:db8::fe".parse().unwrap()
                    } else {
                        "192.0.2.254".parse().unwrap()
                    }
                } else {
                    quote.destination
                };
                let protocol = if ipv6 {
                    wire::PROTO_ICMPV6
                } else {
                    wire::PROTO_ICMP
                };
                let expected = Tuple {
                    source: if router_error {
                        source
                    } else {
                        restored.destination
                    },
                    destination: restored.source,
                    protocol,
                    source_port: 0,
                    destination_port: 0,
                };
                let quoted_packet = udp(quote);
                let header_len = if ipv6 { 40 } else { 20 };
                let mut error = vec![0; header_len + 8 + quoted_packet.len()];
                wire::emit_ip_header(
                    &mut error,
                    source,
                    quote.source,
                    protocol,
                    8 + quoted_packet.len(),
                )
                .unwrap();
                error[header_len] = if ipv6 { 1 } else { 3 };
                error[header_len + 1] = if ipv6 { 0 } else { 1 };
                error[header_len + 8..].copy_from_slice(&quoted_packet);
                let mut checksum = if ipv6 {
                    Checksum::pseudo(source, quote.source, protocol, error.len() - header_len)
                } else {
                    Checksum::new()
                };
                checksum.add(&error[header_len..]);
                error[header_len + 2..header_len + 4]
                    .copy_from_slice(&checksum.finish().to_be_bytes());
                let related = table
                    .lookup(input, &Facts::parse(&error).unwrap(), now)
                    .unwrap()
                    .unwrap();
                assert_eq!(related.egress_ingress(), output);
                assert_eq!(related.before_route(), expected);
                assert_eq!(related.after_route(), expected);
                related.rewrite(&mut error, true).unwrap();
                related.rewrite(&mut error, false).unwrap();
                assert_eq!(Facts::parse(&error).unwrap().tuple, expected);
                assert_eq!(
                    Facts::parse(&error[header_len + 8..]).unwrap().tuple,
                    restored
                );
            }
        }
    }
}

#[test]
fn related_echo_quote_remains_checksum_valid_when_its_data_are_all_zero() {
    fn echo(tuple: Tuple, reply: bool, sequence: u16) -> Vec<u8> {
        let mut bytes = vec![0; 28];
        wire::emit_ip_header(
            &mut bytes,
            tuple.source,
            tuple.destination,
            wire::PROTO_ICMP,
            8,
        )
        .unwrap();
        bytes[20] = if reply { 0 } else { 8 };
        bytes[24..26].copy_from_slice(&tuple.source_port.to_be_bytes());
        bytes[26..28].copy_from_slice(&sequence.to_be_bytes());
        let checksum = wire::checksum::checksum(&bytes[20..]);
        bytes[22..24].copy_from_slice(&checksum.to_be_bytes());
        bytes
    }
    let now = Instant::now();
    let original = tuple("10.0.0.2:0", "192.0.2.9:0", wire::PROTO_ICMP);
    let nonzero = Tuple {
        source_port: 1,
        destination_port: 1,
        ..original.reverse()
    };
    for checksum in [0u16, u16::MAX] {
        let mut valid = echo(nonzero, true, 0xfffe);
        valid[22..24].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(Facts::parse(&valid).unwrap().tuple, nonzero);
    }
    let mut invalid = echo(original.reverse(), true, 0);
    assert_eq!(&invalid[20..], &[0, 0, 0xff, 0xff, 0, 0, 0, 0]);
    invalid[22..24].fill(0);
    assert!(Facts::parse(&invalid).is_err());
    let mut table = table();
    let binding = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &Facts::parse(&echo(original, false, 0)).unwrap(),
            dnat: None,
            snat: SourceNat::Snat {
                address: "198.51.100.1".parse().unwrap(),
                ports: None,
            },
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    let mut reply = echo(binding.after_route().reverse(), true, 0);
    let lease = table
        .lookup(ingress(2), &Facts::parse(&reply).unwrap(), now)
        .unwrap()
        .unwrap();
    lease.rewrite(&mut reply, false).unwrap();
    let mut error = quoted_error(&reply);
    let related = table
        .lookup(ingress(1), &Facts::parse(&error).unwrap(), now)
        .unwrap()
        .unwrap();
    related.rewrite(&mut error, false).unwrap();
    assert_eq!(
        Facts::parse(&error[28..]).unwrap().tuple,
        binding.after_route().reverse()
    );
    let view = wire::PacketView::from_slice(&error[28..]);
    assert!(view.transport_ports(&view.parse_ip().unwrap()).is_ok());
    assert_eq!(wire::checksum::checksum(&error[20..]), 0);
}

#[test]
fn udp_nat_checks_declared_length_and_preserves_ip_trailer() {
    let now = Instant::now();
    let original = tuple("10.0.0.2:1234", "192.0.2.9:53", wire::PROTO_UDP);
    for checksum_enabled in [false, true] {
        let mut table = table();
        let mut bytes = udp(original);
        let udp_end = bytes.len();
        bytes.extend_from_slice(b"trailer");
        let length = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        if !checksum_enabled {
            bytes[26..28].fill(0);
        }
        seal_ipv4(&mut bytes);
        let facts = Facts::parse(&bytes).unwrap();
        let lease = table
            .admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &facts,
                dnat: None,
                snat: snat(),
                egress: None,
                received_at: now,
                now,
            })
            .unwrap();
        lease.rewrite(&mut bytes, false).unwrap();
        assert_eq!(Facts::parse(&bytes).unwrap().tuple, lease.after_route());
        assert_eq!(&bytes[udp_end..], b"trailer");
        assert_eq!(&bytes[28..udp_end], b"proof");
        assert!(wire::udp::verify_checksum(
            lease.after_route().source,
            lease.after_route().destination,
            &bytes[20..],
        ));
        assert_eq!(bytes[26..28] != [0, 0], checksum_enabled);
    }
}
