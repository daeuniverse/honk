use super::*;
#[test]
fn snat_equal_ids_zero_udp_interleaved_fragments_keep_exact_payloads() {
    use crate::forward::{CoreForward, ForwardError};
    let now = Instant::now();
    // Both local fragmentation and a smaller MTU only at the next router need unique IDs.
    for downstream_fragmentation in [false, true] {
        let budget = MemoryBudget::new(64 << 20);
        let mut core = CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
        let mut downstream =
            CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
        let mut receiver = CoreForward::new(&[ingress(2)], Arc::clone(&budget), 8).unwrap();
        let mut table = Firewall::new(budget, 8, 1).unwrap();
        let mut packets = Vec::new();
        let mut expected = Vec::new();
        for (source, value) in [("10.0.0.2:1000", 0x11), ("10.0.0.3:1000", 0x77)] {
            let original = tuple(source, "192.0.2.9:53", wire::PROTO_UDP);
            let payload = vec![value; 80];
            let bytes = fragmentable_udp(original, 0xabcd, &payload);
            let mut packet = if downstream_fragmentation {
                core.receive(ingress(1), now, &bytes).unwrap().unwrap()
            } else {
                let packet = downstream
                    .receive(ingress(1), now, &bytes)
                    .unwrap()
                    .unwrap();
                let fragments = forward_datagram(&mut downstream, packet, 68, 2, now);
                assert!(
                    core.receive(ingress(1), now, &fragments[0].0)
                        .unwrap()
                        .is_none()
                );
                core.receive(ingress(1), now, &fragments[1].0)
                    .unwrap()
                    .unwrap()
            };
            let received_bytes = packet.as_ref().to_vec();
            let facts = Facts::from_packet(&packet).unwrap();
            let binding = table
                .admit(Admission {
                    ingress: ingress(1),
                    reply_ingress: ingress(2),
                    facts: &facts,
                    dnat: None,
                    snat: SourceNat::Snat {
                        address: "198.51.100.1".parse().unwrap(),
                        ports: Some(PortPool {
                            first: 40000,
                            last: 40001,
                        }),
                    },
                    egress: None,
                    received_at: now,
                    now,
                })
                .unwrap();
            expected.push((binding.after_route(), payload));
            packet
                .rewrite(|bytes| {
                    binding
                        .rewrite(bytes, false)
                        .map_err(|_| ForwardError::Provenance)
                })
                .unwrap();
            let mut restored = packet.as_ref().to_vec();
            facts.restore(&mut restored).unwrap();
            assert_eq!(
                restored, received_bytes,
                "local ICMP rollback restores the ingress ID too"
            );
            packet.bind(binding);
            let mut fragments = forward_datagram(
                &mut core,
                packet,
                if downstream_fragmentation { 1500 } else { 68 },
                2,
                now,
            );
            if downstream_fragmentation {
                assert_eq!(fragments.len(), 1);
                let packet = downstream
                    .receive(ingress(1), now, &fragments[0].0)
                    .unwrap()
                    .unwrap();
                fragments = forward_datagram(&mut downstream, packet, 68, 2, now);
            }
            assert_eq!(fragments.len(), 2);
            assert_eq!(&fragments[0].0[26..28], &[0, 0]);
            assert_eq!(&fragments[0].0[4..6], &fragments[1].0[4..6]);
            packets.push(fragments);
        }
        let mut received = 0;
        for (datagram, fragment) in [(0, 0), (1, 1), (1, 0), (0, 1)] {
            if let Some(packet) = receiver
                .receive(ingress(2), now, &packets[datagram][fragment].0)
                .unwrap()
            {
                let facts = Facts::from_packet(&packet).unwrap();
                let (_, payload) = expected
                    .iter()
                    .find(|(tuple, _)| *tuple == facts.tuple)
                    .unwrap();
                assert_eq!(
                    &packet.as_ref()[28..],
                    payload.as_slice(),
                    "cross-source reassembly mixed payloads"
                );
                received += 1;
            }
        }
        assert_eq!(received, 2);
        assert_ne!(&packets[0][0].0[4..6], &packets[1][0].0[4..6]);
    }
}

#[test]
fn nat_fragment_quotes_restore_original_and_reply_ids_without_guessing_ports() {
    use crate::forward::{CoreForward, ForwardError};
    let now = Instant::now();
    let budget = MemoryBudget::new(32 << 20);
    let mut core = CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
    let mut table = Firewall::new(budget, 8, 1).unwrap();
    let original = tuple("10.0.0.2:1000", "192.0.2.9:53", wire::PROTO_UDP);
    let request = fragmentable_udp(original, 0xabcd, &[0x11; 80]);
    let binding = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &Facts::parse(&request).unwrap(),
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    let translated = binding.after_route();
    let mut delayed = None;
    for reply in [false, true] {
        let (bytes, lease, input, egress, expected_id, restored) = if reply {
            let bytes = fragmentable_udp(translated.reverse(), 0xbeef, &[0x77; 80]);
            let lease = table
                .lookup(ingress(2), &Facts::parse(&bytes).unwrap(), now)
                .unwrap()
                .unwrap();
            (bytes, lease, ingress(2), 1, 0xbeef, translated.reverse())
        } else {
            (
                request.clone(),
                binding.clone(),
                ingress(1),
                2,
                0xabcd,
                original,
            )
        };
        let mut packet = core.receive(input, now, &bytes).unwrap().unwrap();
        packet
            .rewrite(|bytes| {
                lease
                    .rewrite(bytes, false)
                    .map_err(|_| ForwardError::Provenance)
            })
            .unwrap();
        packet.bind(lease);
        let fragments = forward_datagram(&mut core, packet, 68, egress, now);
        for (index, (fragment, _)) in fragments.iter().enumerate() {
            let quote = &fragment[..28];
            if !reply && index == 1 {
                delayed = Some(quoted_error(quote));
            }
            let mut error = quoted_error(quote);
            let related = table
                .lookup(ingress(egress), &Facts::parse(&error).unwrap(), now)
                .unwrap()
                .unwrap();
            related.rewrite(&mut error, true).unwrap();
            related.rewrite(&mut error, false).unwrap();
            assert_eq!(
                u16::from_be_bytes(error[32..34].try_into().unwrap()),
                expected_id
            );
            assert_eq!(
                &error[40..44],
                match restored.source {
                    IpAddr::V4(ip) => ip.octets(),
                    _ => unreachable!(),
                }
                .as_slice()
            );
            assert_eq!(
                &error[44..48],
                match restored.destination {
                    IpAddr::V4(ip) => ip.octets(),
                    _ => unreachable!(),
                }
                .as_slice()
            );
            assert_eq!(wire::checksum::checksum(&error[28..48]), 0);
            assert_eq!(wire::checksum::checksum(&error[20..]), 0);
            if index == 0 {
                assert_eq!(quoted_tuple(&error[28..]).unwrap(), restored);
                assert_eq!(&error[54..56], &[0, 0]);
            } else {
                assert_eq!(
                    &error[48..],
                    &quote[20..],
                    "non-first payload is not a transport header"
                );
            }
            let mut unknown = quote.to_vec();
            unknown[4..6].copy_from_slice(&60000u16.to_be_bytes());
            seal_ipv4(&mut unknown);
            let error = quoted_error(&unknown);
            assert!(matches!(
                table.lookup(ingress(egress), &Facts::parse(&error).unwrap(), now),
                Err(FirewallError::Denied)
            ));
        }
    }
    drop(binding);
    table.expire(now);
    let mut delayed = delayed.unwrap();
    let late = now + Duration::from_secs(40);
    let held_quote = table
        .lookup(ingress(2), &Facts::parse(&delayed).unwrap(), late)
        .unwrap()
        .unwrap();
    held_quote.rewrite(&mut delayed, false).unwrap();
    assert_eq!(
        u16::from_be_bytes(delayed[32..34].try_into().unwrap()),
        0xabcd
    );
    table.revoke(2);
    let returned = now + Duration::from_secs(1000);
    table.expire(returned);
    assert_eq!(
        table.identities.len(),
        1,
        "a delayed quote retains the retired original identity"
    );
    drop(held_quote);
    table.expire(returned);
    table.expire(returned + IPV4_ID_LIFETIME - Duration::from_nanos(1));
    assert_eq!(table.identities.len(), 1);
    table.expire(returned + IPV4_ID_LIFETIME);
    assert!(table.is_empty());
}

#[test]
fn nat_id_exhaustion_and_retirement_quarantine_keep_aliases_and_budget_bounded() {
    let now = Instant::now();
    let budget = MemoryBudget::new(1 << 20);
    let mut table = Firewall::new(Arc::clone(&budget), 2, 1).unwrap();
    let original = tuple("10.0.0.2:1000", "192.0.2.9:53", wire::PROTO_UDP);
    let facts = Facts::parse(&fragmentable_udp(original, 0xabcd, b"proof")).unwrap();
    let action = SourceNat::Snat {
        address: "198.51.100.1".parse().unwrap(),
        ports: Some(PortPool {
            first: 40000,
            last: 40001,
        }),
    };
    let held_output = table
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
    let first_id = held_output.identity.as_ref().unwrap().output_id;
    for _ in 1..table.identity_capacity {
        drop(table.lookup(ingress(1), &facts, now).unwrap().unwrap());
    }
    let used = budget.used();
    assert!(matches!(
        table.lookup(ingress(1), &facts, now),
        Err(FirewallError::Exhausted)
    ));
    let second = tuple("10.0.0.3:1001", "192.0.2.9:53", wire::PROTO_UDP);
    let second_facts = Facts::parse(&fragmentable_udp(second, 0xabcd, b"second")).unwrap();
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &second_facts,
            dnat: None,
            snat: action,
            egress: None,
            received_at: now,
            now,
        }),
        Err(FirewallError::Exhausted)
    ));
    assert_eq!(table.entries.len(), 1);
    assert_eq!(table.identities.len(), table.identity_capacity);
    assert_eq!(budget.used(), used);
    assert_eq!(table.entries[0].last, now);
    // Atomic datagrams consume neither identities nor the exhausted datagram quota.
    let atomic = Facts::parse(&udp(second)).unwrap();
    let lease = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &atomic,
            dnat: None,
            snat: action,
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    assert!(lease.identity.is_none());
    assert_eq!(lease.after_route().source_port, 40001);
    drop(lease);
    table.revoke(2);
    let later = now + Duration::from_secs(1000);
    table.expire(later);
    table.expire(later + IPV4_ID_LIFETIME);
    assert_eq!(
        table.identities.len(),
        1,
        "CQ-held identity outlives its allocation time and epoch"
    );
    assert_ne!(
        table.id_bits[usize::from(first_id) / 64] & (1u64 << (first_id % 64)),
        0
    );
    drop(held_output);
    table.set_fragment_obligations(std::iter::once(obligation(ingress(1), original)));
    let retired = later + Duration::from_secs(1000);
    table.expire(retired);
    assert_eq!(
        table.identities.len(),
        1,
        "late ingress fragments retain restoration authority"
    );
    table.set_fragment_obligations(std::iter::empty());
    table.expire(retired);
    table.expire(retired + IPV4_ID_LIFETIME - Duration::from_nanos(1));
    assert_eq!(table.identities.len(), 1);
    table.expire(retired + IPV4_ID_LIFETIME);
    assert!(table.identities.is_empty());
    assert!(table.entries.is_empty());
    assert!(table.id_bits.iter().all(|word| *word == 0));
    drop(table);
    assert_eq!(budget.used(), 0);
}

#[test]
fn nat_id_budget_failure_rolls_back_binding_and_port_publication() {
    let now = Instant::now();
    let budget = MemoryBudget::new(1 << 20);
    let mut table = Firewall::new(Arc::clone(&budget), 1, 1).unwrap();
    let facts = Facts::parse(&fragmentable_udp(
        tuple("10.0.0.2:1000", "192.0.2.9:53", 17),
        7,
        b"proof",
    ))
    .unwrap();
    let available = size_of::<Binding>() + 2 * size_of::<usize>();
    let pressure = budget
        .reserve((1 << 20) - budget.used() - available)
        .unwrap();
    let used = budget.used();
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &facts,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now,
        }),
        Err(FirewallError::Capacity)
    ));
    assert!(table.entries.is_empty());
    assert!(table.identities.is_empty());
    assert!(table.id_bits.iter().all(|word| *word == 0));
    assert_eq!(budget.used(), used);
    drop(pressure);
    assert!(
        table
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
            .is_ok()
    );
}
#[test]
fn failed_related_lease_keeps_the_original_identity_quarantine_deadline() {
    let now = Instant::now();
    let mut table = Firewall::new(MemoryBudget::new(1 << 20), 1, 1).unwrap();
    let original = tuple("10.0.0.2:1000", "192.0.2.9:53", wire::PROTO_UDP);
    let mut bytes = fragmentable_udp(original, 7, b"proof");
    let facts = Facts::parse(&bytes).unwrap();
    let binding = table
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
    binding.rewrite(&mut bytes, false).unwrap();
    drop(binding);
    for _ in 1..table.identity_capacity {
        drop(table.lookup(ingress(1), &facts, now).unwrap().unwrap());
    }
    table.expire(now);
    let mut error = quoted_error(&bytes[..28]);
    error[6..8].fill(0);
    seal_ipv4(&mut error);
    assert!(matches!(
        table.lookup(
            ingress(2),
            &Facts::parse(&error).unwrap(),
            now + Duration::from_secs(1)
        ),
        Err(FirewallError::Exhausted)
    ));
    assert_eq!(table.identities[0].retired_at, Some(now));
    table.expire(now + IPV4_ID_LIFETIME);
    assert!(table.identities.is_empty());
}

#[test]
fn exhausted_ids_become_allocatable_only_at_the_exact_mdl_deadline() {
    let now = Instant::now();
    let mut table = Firewall::new(MemoryBudget::new(1 << 20), 1, 1).unwrap();
    let original = tuple("10.0.0.2:1000", "192.0.2.9:53", wire::PROTO_UDP);
    let facts = Facts::parse(&fragmentable_udp(original, 7, b"proof")).unwrap();
    let first = table
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
    let first_id = first.identity.as_ref().unwrap().output_id;
    drop(first);
    for _ in 1..table.identity_capacity {
        drop(table.lookup(ingress(1), &facts, now).unwrap().unwrap());
    }
    table.expire(now);
    let just_before = now + IPV4_ID_LIFETIME - Duration::from_nanos(1);
    assert!(matches!(
        table.lookup(ingress(1), &facts, just_before),
        Err(FirewallError::Exhausted)
    ));
    let recovered = now + IPV4_ID_LIFETIME;
    let next = Facts::parse(&fragmentable_udp(
        tuple("10.0.0.3:1001", "192.0.2.9:53", wire::PROTO_UDP),
        7,
        b"next",
    ))
    .unwrap();
    let lease = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &next,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: recovered,
            now: recovered,
        })
        .unwrap();
    assert_eq!(lease.identity.as_ref().unwrap().output_id, first_id);
    let mut packet = fragmentable_udp(next.tuple, 7, b"next");
    lease.rewrite(&mut packet, false).unwrap();
    assert_eq!(Facts::parse(&packet).unwrap().tuple, lease.after_route());
}

#[test]
fn related_budget_refusal_does_not_restart_the_quoted_identity_mdl() {
    let now = Instant::now();
    let budget = MemoryBudget::new(1 << 20);
    let mut table = Firewall::new(Arc::clone(&budget), 1, 1).unwrap();
    let original = tuple("10.0.0.2:1000", "192.0.2.9:53", wire::PROTO_UDP);
    let mut packet = fragmentable_udp(original, 7, b"proof");
    let lease = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &Facts::parse(&packet).unwrap(),
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    lease.rewrite(&mut packet, false).unwrap();
    let old_id = lease.identity.as_ref().unwrap().output_id;
    drop(lease);
    table.expire(now);
    let pressure = budget.reserve((1 << 20) - budget.used()).unwrap();
    let mut error = quoted_error(&packet[..28]);
    error[6..8].fill(0);
    seal_ipv4(&mut error);
    assert!(matches!(
        table.lookup(
            ingress(2),
            &Facts::parse(&error).unwrap(),
            now + Duration::from_secs(1)
        ),
        Err(FirewallError::Capacity)
    ));
    assert_eq!(table.identities[0].retired_at, Some(now));
    drop(pressure);
    let recovered = now + IPV4_ID_LIFETIME;
    let facts = Facts::parse(&fragmentable_udp(original, 7, b"proof")).unwrap();
    let lease = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &facts,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: recovered,
            now: recovered,
        })
        .unwrap();
    assert_eq!(lease.identity.as_ref().unwrap().output_id, old_id);
}
