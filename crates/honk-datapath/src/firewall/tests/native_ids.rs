use super::*;
use crate::forward::{CoreForward, ForwardError, ForwardLease};

fn destination_nat() -> DestinationNat {
    DestinationNat {
        address: "10.0.1.8".parse().unwrap(),
        port: Some(80),
    }
}

fn admit_bytes(
    table: &mut Firewall,
    bytes: &[u8],
    dnat: Option<DestinationNat>,
    now: Instant,
) -> Result<BindingLease, FirewallError> {
    table.admit(Admission {
        ingress: ingress(1),
        reply_ingress: ingress(2),
        facts: &Facts::parse(bytes).unwrap(),
        dnat,
        snat: SourceNat::None,
        egress: None,
        received_at: now,
        now,
    })
}

fn emit_fragments(
    table: &mut Firewall,
    core: &mut CoreForward,
    original: Tuple,
    dnat: Option<DestinationNat>,
    payload: u8,
    mtu: u32,
    now: Instant,
) -> Vec<(Vec<u8>, ForwardLease)> {
    let bytes = fragmentable_udp(original, 0, &[payload; 80]);
    let mut packet = core.receive(ingress(1), now, &bytes).unwrap().unwrap();
    let binding = admit_bytes(table, &bytes, dnat, now).unwrap();
    if binding.translation_required() {
        packet
            .rewrite(|bytes| {
                binding
                    .rewrite(bytes, false)
                    .map_err(|_| ForwardError::Provenance)
            })
            .unwrap();
    }
    packet.bind(binding);
    forward_datagram(core, packet, mtu, 2, now)
}

fn reconstruct(
    receiver: &mut CoreForward,
    packets: &[Vec<Vec<u8>>],
    expected: [(u16, u8); 2],
    now: Instant,
) {
    let mut received = Vec::new();
    for (datagram, fragment) in [(0, 0), (1, 1), (1, 0), (0, 1)] {
        if let Some(packet) = receiver
            .receive(ingress(2), now, &packets[datagram][fragment])
            .unwrap()
        {
            let facts = Facts::from_packet(&packet).unwrap();
            let (port, value) = expected
                .iter()
                .find(|(port, _)| *port == facts.tuple.source_port)
                .copied()
                .unwrap();
            assert_eq!(&packet.as_ref()[26..28], &[0, 0]);
            assert_eq!(&packet.as_ref()[28..], &[value; 80]);
            received.push(port);
        }
    }
    received.sort_unstable();
    let mut ports = expected.map(|(port, _)| port);
    ports.sort_unstable();
    assert_eq!(received, ports);
}

#[test]
fn plain_and_dnat_reconstruct_zero_checksum_payloads_in_both_arrival_orders() {
    let now = Instant::now();
    for native_first in [false, true] {
        for downstream_fragmentation in [false, true] {
            let budget = MemoryBudget::new(64 << 20);
            let mut table = Firewall::new(Arc::clone(&budget), 8, 1).unwrap();
            let mut core =
                CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
            let mut downstream =
                CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
            let mut receiver = CoreForward::new(&[ingress(2)], budget, 8).unwrap();
            let original = tuple("10.0.0.2:1000", "198.51.100.1:8080", wire::PROTO_UDP);
            let plain = tuple("10.0.0.2:1001", "10.0.1.8:80", wire::PROTO_UDP);
            let order = if native_first {
                [
                    (plain, None, 0x77),
                    (original, Some(destination_nat()), 0x11),
                ]
            } else {
                [
                    (original, Some(destination_nat()), 0x11),
                    (plain, None, 0x77),
                ]
            };
            let mut packets = Vec::new();
            for (original, action, value) in order {
                let mut fragments = emit_fragments(
                    &mut table,
                    &mut core,
                    original,
                    action,
                    value,
                    if downstream_fragmentation { 1500 } else { 68 },
                    now,
                );
                if downstream_fragmentation {
                    let packet = downstream
                        .receive(ingress(1), now, &fragments[0].0)
                        .unwrap()
                        .unwrap();
                    fragments = forward_datagram(&mut downstream, packet, 68, 2, now);
                }
                assert_eq!(fragments.len(), 2);
                packets.push(
                    fragments
                        .into_iter()
                        .map(|(bytes, _)| bytes)
                        .collect::<Vec<_>>(),
                );
            }
            reconstruct(&mut receiver, &packets, [(1000, 0x11), (1001, 0x77)], now);
            assert_ne!(&packets[0][0][4..6], &packets[1][0][4..6]);
        }
    }
}

#[test]
fn inactive_and_revoked_native_or_managed_history_survives_cq_and_quarantine() {
    let now = Instant::now();
    for native_first in [false, true] {
        for reload in [false, true] {
            let budget = MemoryBudget::new(32 << 20);
            let mut table = Firewall::new(Arc::clone(&budget), 8, 1).unwrap();
            let mut core =
                CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
            let mut receiver = CoreForward::new(&[ingress(2)], budget, 8).unwrap();
            let nat = tuple("10.0.0.2:1000", "198.51.100.1:8080", wire::PROTO_UDP);
            let plain = tuple("10.0.0.2:1001", "10.0.1.8:80", wire::PROTO_UDP);
            let (first, action, marker) = if native_first {
                (plain, None, 0x77)
            } else {
                (nat, Some(destination_nat()), 0x11)
            };
            let first = emit_fragments(&mut table, &mut core, first, action, marker, 68, now);
            let returned = now + UDP_IDLE_TIMEOUT;
            if reload {
                table.revoke(2);
            }
            table.expire(returned);
            assert!(!table.entries[0].binding.active.load(Ordering::Acquire));
            let first: Vec<_> = first.into_iter().map(|(bytes, _)| bytes).collect();
            table.expire(returned);
            let later = returned + Duration::from_secs(1);
            let (next, action, marker) = if native_first {
                (nat, Some(destination_nat()), 0x11)
            } else {
                (plain, None, 0x77)
            };
            let second = emit_fragments(&mut table, &mut core, next, action, marker, 68, later);
            let second: Vec<_> = second.into_iter().map(|(bytes, _)| bytes).collect();
            let ids_differ = first[0][4..6] != second[0][4..6];
            if !native_first {
                let original_id = u16::from_be_bytes(first[0][4..6].try_into().unwrap());
                for fragment in &second {
                    let mut error = quoted_error(&fragment[..28]);
                    let related = table
                        .lookup(ingress(2), &Facts::parse(&error).unwrap(), later)
                        .unwrap()
                        .unwrap();
                    related.rewrite(&mut error, false).unwrap();
                    assert_eq!(
                        u16::from_be_bytes(error[32..34].try_into().unwrap()),
                        original_id
                    );
                    assert!(Facts::parse(&error).is_ok());
                    assert_eq!(wire::checksum::checksum(&error[28..48]), 0);
                }
            }
            reconstruct(
                &mut receiver,
                &[first, second],
                [(1000, 0x11), (1001, 0x77)],
                later,
            );
            assert!(ids_differ);
        }
    }
}

#[test]
fn repeated_raw_ids_have_no_managed_pool_packet_rate_limit_or_cross_domain_blacklist() {
    let now = Instant::now();
    let mut table = table();
    let plain = tuple("10.0.0.2:1001", "10.0.1.8:80", wire::PROTO_UDP);
    let other = tuple("10.0.0.3:1002", "10.0.1.8:80", wire::PROTO_UDP);
    for (original, id) in [(plain, 0), (other, 1)] {
        let bytes = fragmentable_udp(original, id, b"native");
        let facts = Facts::parse(&bytes).unwrap();
        let lease = admit_bytes(&mut table, &bytes, None, now).unwrap();
        assert!(!lease.translation_required());
        drop(lease);
        for _ in 0..2 * table.identity_capacity {
            let lease = table.lookup(ingress(1), &facts, now).unwrap().unwrap();
            assert!(!lease.translation_required());
            assert!(lease.identity.is_none());
        }
    }
    assert_eq!(table.native_history.len(), 2);
    assert!(table.identities.is_empty());
    let bytes = fragmentable_udp(
        tuple("10.0.0.2:1000", "198.51.100.1:8080", wire::PROTO_UDP),
        0,
        b"translated",
    );
    let lease = admit_bytes(&mut table, &bytes, Some(destination_nat()), now).unwrap();
    assert_eq!(
        lease.identity.as_ref().unwrap().output_id,
        1,
        "an unrelated native domain's ID must remain allocatable"
    );
}

#[test]
fn native_history_overflow_keeps_plain_output_and_unknown_id_quarantine_bounded() {
    let now = Instant::now();
    let budget = MemoryBudget::new(4 << 20);
    let mut table = Firewall::new_history(Arc::clone(&budget), 4, 1).unwrap();
    let plain = tuple("10.0.0.2:1001", "10.0.1.8:80", wire::PROTO_UDP);
    for id in 0..table.identity_capacity as u16 {
        let lease = table
            .observe_plain(ingress(1), ingress(2), plain, id, now)
            .unwrap();
        assert!(lease.is_exact());
    }
    assert!(table.entries.is_empty());
    assert!(table._state_charge.is_none());
    let held = table
        .observe_plain(ingress(1), ingress(2), plain, u16::MAX, now)
        .unwrap();
    assert!(!held.is_exact());
    let cq_copy = held.clone();
    let independent = fragmentable_udp(
        tuple("10.0.0.3:1000", "198.51.100.1:8080", wire::PROTO_UDP),
        0,
        b"independent",
    );
    table.next_id_word = IPV4_ID_WORDS - 1;
    let mut held_nat =
        vec![admit_bytes(&mut table, &independent, Some(destination_nat()), now).unwrap()];
    for _ in 1..63 {
        held_nat.push(
            table
                .lookup(ingress(1), &Facts::parse(&independent).unwrap(), now)
                .unwrap()
                .unwrap(),
        );
    }
    let probe = |port| {
        fragmentable_udp(
            tuple(
                &format!("10.0.0.2:{port}"),
                "198.51.100.1:8080",
                wire::PROTO_UDP,
            ),
            0,
            b"probe",
        )
    };
    let output = admit_bytes(&mut table, &probe(1000), Some(destination_nat()), now).unwrap();
    assert_ne!(output.identity.as_ref().unwrap().output_id, u16::MAX);
    drop(output);
    table.expire(now);
    table.revoke(2);
    let returned = now + 3 * IPV4_ID_LIFETIME;
    drop(held);
    table.expire(returned);
    assert_ne!(table.overflow_bits[IPV4_ID_WORDS - 1] & (1u64 << 63), 0);
    drop(cq_copy);
    table.expire(returned);
    table.expire(returned + IPV4_ID_LIFETIME);
    assert_ne!(
        table.overflow_bits[IPV4_ID_WORDS - 1] & (1u64 << 63),
        0,
        "an unknown ID also covers the bounded local reassembly horizon"
    );
    let pinned_at = returned + overflow_lifetime() - Duration::from_nanos(1);
    let mut error = quoted_error(&fragmentable_udp(plain, u16::MAX, b"native quote"));
    let quote = table
        .retain_native_quote(ingress(2), &Facts::parse(&error).unwrap())
        .unwrap();
    let quote_cq = quote.clone();
    quote.rewrite(&mut error).unwrap();
    assert!(Facts::parse(&error).is_ok());
    drop(quote);
    drop(quote_cq);
    // No expire ran while the quote guard was held: acquisition must clear the old tick.
    table.expire(pinned_at);
    table.next_id_word = IPV4_ID_WORDS - 1;
    let before = pinned_at + overflow_lifetime() - Duration::from_nanos(1);
    let output = admit_bytes(&mut table, &probe(1001), Some(destination_nat()), before).unwrap();
    assert_ne!(output.identity.as_ref().unwrap().output_id, u16::MAX);
    drop(output);
    table.next_id_word = IPV4_ID_WORDS - 1;
    let recovered = pinned_at + overflow_lifetime();
    let mut bytes = probe(1002);
    let output = admit_bytes(&mut table, &bytes, Some(destination_nat()), recovered).unwrap();
    assert_eq!(output.identity.as_ref().unwrap().output_id, u16::MAX);
    output.rewrite(&mut bytes, false).unwrap();
    assert_eq!(Facts::parse(&bytes).unwrap().tuple, output.after_route());
    drop(output);
    drop(held_nat);
    drop(table);
    assert_eq!(budget.used(), 0);
}

#[test]
fn native_history_budget_refusal_keeps_plain_forwarding_funded_by_its_fallback() {
    let now = Instant::now();
    let budget = MemoryBudget::new(1 << 20);
    let mut table = Firewall::new(Arc::clone(&budget), 2, 1).unwrap();
    let plain = tuple("10.0.0.2:1001", "10.0.1.8:80", wire::PROTO_UDP);
    drop(
        admit_bytes(
            &mut table,
            &fragmentable_udp(plain, 0, b"native"),
            None,
            now,
        )
        .unwrap(),
    );
    let pressure = budget.reserve((1 << 20) - budget.used()).unwrap();
    let charged = budget.used();
    for id in [1, 2, 3] {
        let bytes = fragmentable_udp(plain, id, b"still native");
        let lease = table
            .lookup(ingress(1), &Facts::parse(&bytes).unwrap(), now)
            .unwrap()
            .unwrap();
        assert!(!lease.translation_required());
        assert!(!lease._native_identity.as_ref().unwrap().is_exact());
        assert_eq!(budget.used(), charged);
    }
    assert_eq!(table.native_history.len(), 1);
    drop(pressure);
    drop(table);
    assert_eq!(budget.used(), 0);
}

#[test]
fn prepolicy_history_has_no_grant_and_repairs_unbound_quotes_after_reload() {
    let now = Instant::now();
    let budget = MemoryBudget::new(4 << 20);
    let mut table = Firewall::new_history(Arc::clone(&budget), 4, 1).unwrap();
    let plain = tuple("10.0.0.2:1001", "10.0.1.8:80", wire::PROTO_UDP);
    let held_plain = table
        .observe_plain(ingress(1), ingress(2), plain, 0, now)
        .unwrap();
    assert!(table.is_empty());
    assert!(table._state_charge.is_none());
    let nat = fragmentable_udp(
        tuple("10.0.0.2:1000", "198.51.100.1:8080", wire::PROTO_UDP),
        0,
        b"translated",
    );
    table.revoke(2);
    let nat = admit_bytes(&mut table, &nat, Some(destination_nat()), now).unwrap();
    assert_eq!(nat.identity.as_ref().unwrap().output_id, 1);
    let remapped = table
        .observe_plain(ingress(1), ingress(2), plain, 1, now)
        .unwrap();
    assert_ne!(remapped.output_id(), 1);
    assert_eq!(
        table.entries.len(),
        1,
        "native output history must not become conntrack"
    );
    let mut bytes = fragmentable_udp(plain, 1, b"plain");
    remapped.rewrite(&mut bytes).unwrap();
    let mut error = quoted_error(&bytes);
    let facts = Facts::parse(&error).unwrap();
    assert!(table.retain_native_quote(ingress(3), &facts).is_none());
    let quote = table.retain_native_quote(ingress(2), &facts).unwrap();
    drop(held_plain);
    drop(remapped);
    drop(nat);
    table.revoke(3);
    table.expire(now);
    let returned = now + 2 * IPV4_ID_LIFETIME;
    table.expire(returned);
    assert_eq!(table.identities.len(), 1);
    quote.rewrite(&mut error).unwrap();
    assert_eq!(u16::from_be_bytes(error[32..34].try_into().unwrap()), 1);
    assert!(Facts::parse(&error).is_ok());
    assert_eq!(Facts::parse(&error[28..]).unwrap().tuple, plain);
    drop(quote);
    table.expire(returned);
    table.expire(returned + IPV4_ID_LIFETIME - Duration::from_nanos(1));
    assert_eq!(table.identities.len(), 1);
    table.expire(returned + IPV4_ID_LIFETIME);
    assert!(table.identities.is_empty());
    drop(table);
    assert_eq!(budget.used(), 0);
}

#[test]
fn overflow_output_lease_keeps_its_count_storage_charged_after_history_owner_drop() {
    let now = Instant::now();
    let budget = MemoryBudget::new(1 << 20);
    let mut table = Firewall::new_history(Arc::clone(&budget), 1, 1).unwrap();
    let plain = tuple("10.0.0.2:1001", "10.0.1.8:80", wire::PROTO_UDP);
    let pressure = budget.reserve((1 << 20) - budget.used()).unwrap();
    let output = table
        .observe_plain(ingress(1), ingress(2), plain, 7, now)
        .unwrap();
    assert!(!output.is_exact());
    let cq_copy = output.clone();
    drop(pressure);
    drop(table);
    let retained = budget.used();
    assert!(retained >= 65536 * (size_of::<AtomicU32>() + size_of::<AtomicU64>()));
    drop(output);
    assert_eq!(budget.used(), retained);
    let mut bytes = fragmentable_udp(plain, 7, b"retained");
    cq_copy.rewrite(&mut bytes).unwrap();
    assert_eq!(Facts::parse(&bytes).unwrap().tuple, plain);
    drop(cq_copy);
    assert_eq!(budget.used(), 0);
}

#[test]
fn native_partial_quote_export_pins_only_its_exact_domain_across_first_policy_enable() {
    let now = Instant::now();
    let budget = MemoryBudget::new(4 << 20);
    let mut table = Firewall::new_history(Arc::clone(&budget), 4, 0).unwrap();
    let first = tuple("10.0.0.2:1001", "10.0.1.8:80", wire::PROTO_UDP);
    let other = tuple("10.0.0.3:1002", "10.0.1.8:80", wire::PROTO_UDP);
    for (original, id) in [(first, 0), (other, 1)] {
        drop(
            table
                .observe_plain(ingress(1), ingress(2), original, id, now)
                .unwrap(),
        );
    }
    let pending = FragmentObligation {
        ingress: ingress(2),
        source: "192.0.2.254".parse().unwrap(),
        destination: first.source,
        protocol: wire::PROTO_ICMP,
    };
    table.set_fragment_obligations(std::iter::once(pending));
    table.expire(now);
    let exported = table.retain_fragment(pending).unwrap().unwrap();
    table.set_fragment_obligations(std::iter::empty());
    let published = now + 2 * IPV4_ID_LIFETIME;
    table.expire(published);
    assert_eq!(table.native_history.len(), 1);
    assert_eq!(table.native_history[0].identity.domain.output, first);
    table.revoke(1);
    let nat = fragmentable_udp(
        tuple("10.0.0.2:1000", "198.51.100.1:8080", wire::PROTO_UDP),
        0,
        b"translated",
    );
    let nat = admit_bytes(&mut table, &nat, Some(destination_nat()), published).unwrap();
    assert_eq!(nat.identity.as_ref().unwrap().output_id, 1);
    assert_eq!(
        table.retained_fragments.len(),
        1,
        "enabling conntrack must not replace the exported-history directory"
    );
    let returned = published + IPV4_ID_LIFETIME;
    drop(exported);
    table.expire(returned);
    table.expire(returned + IPV4_ID_LIFETIME - Duration::from_nanos(1));
    assert_eq!(table.native_history.len(), 1);
    table.expire(returned + IPV4_ID_LIFETIME);
    assert!(table.native_history.is_empty());
    drop(nat);
    drop(table);
    assert_eq!(budget.used(), 0);
}

#[test]
fn reply_native_history_keeps_its_real_fragment_ingress_after_grant_revocation() {
    let now = Instant::now();
    let budget = MemoryBudget::new(32 << 20);
    let mut table = Firewall::new(Arc::clone(&budget), 8, 1).unwrap();
    let mut core = CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
    let mut receiver = CoreForward::new(&[ingress(1)], budget, 8).unwrap();
    let original = tuple("10.0.0.2:1000", "198.51.100.9:53", wire::PROTO_UDP);
    drop(admit_bytes(&mut table, &udp(original), None, now).unwrap());
    let reply_tuple = original.reverse();
    let reply = fragmentable_udp(reply_tuple, 0, &[0x77; 80]);
    let binding = table
        .lookup(ingress(2), &Facts::parse(&reply).unwrap(), now)
        .unwrap()
        .unwrap();
    let mut packet = core.receive(ingress(2), now, &reply).unwrap().unwrap();
    packet.bind(binding);
    let fragments = forward_datagram(&mut core, packet, 68, 1, now);
    let fragments: Vec<_> = fragments.into_iter().map(|(bytes, _)| bytes).collect();
    table.revoke(2);
    table.expire(now);
    assert!(
        table.is_empty(),
        "unchanged native IDs must not pin stale grants"
    );

    let fragmented_at = now + IPV4_ID_LIFETIME - Duration::from_secs(1);
    assert!(
        core.receive(ingress(2), fragmented_at, &fragments[0])
            .unwrap()
            .is_none()
    );
    table.set_fragment_obligations(core.fragment_obligations());
    let later = now + IPV4_ID_LIFETIME + Duration::from_secs(1);
    table.expire(later);
    let translated_input = fragmentable_udp(
        tuple("198.51.100.9:2000", "203.0.113.5:8080", wire::PROTO_UDP),
        0,
        &[0x11; 80],
    );
    let mut translated = core
        .receive(ingress(2), later, &translated_input)
        .unwrap()
        .unwrap();
    let binding = table
        .admit(Admission {
            ingress: ingress(2),
            reply_ingress: ingress(1),
            facts: &Facts::from_packet(&translated).unwrap(),
            dnat: Some(DestinationNat {
                address: "10.0.0.2".parse().unwrap(),
                port: Some(1000),
            }),
            snat: SourceNat::None,
            egress: None,
            received_at: later,
            now: later,
        })
        .unwrap();
    translated
        .rewrite(|bytes| {
            binding
                .rewrite(bytes, false)
                .map_err(|_| ForwardError::Provenance)
        })
        .unwrap();
    assert_ne!(
        u16::from_be_bytes(translated.as_ref()[4..6].try_into().unwrap()),
        0,
        "pending reply fragments must preserve their native ID exclusion on the actual input"
    );
    translated.bind(binding);
    let translated = forward_datagram(&mut core, translated, 68, 1, later);

    let mut completed = core
        .receive(ingress(2), later, &fragments[1])
        .unwrap()
        .unwrap();
    table.set_fragment_obligations(core.fragment_obligations());
    let native = table
        .observe_plain(ingress(2), ingress(1), reply_tuple, 0, later)
        .unwrap();
    assert_eq!(native.output_id(), 0);
    completed.bind_native(native);
    let completed = forward_datagram(&mut core, completed, 68, 1, later);
    let datagrams = [translated, completed];
    let mut delivered = Vec::new();
    for (datagram, fragment) in [(0, 0), (1, 1), (1, 0), (0, 1)] {
        if let Some(packet) = receiver
            .receive(ingress(1), later, &datagrams[datagram][fragment].0)
            .unwrap()
        {
            let facts = Facts::from_packet(&packet).unwrap();
            let value = match facts.tuple.source_port {
                53 => 0x77,
                2000 => 0x11,
                _ => panic!("unexpected source"),
            };
            assert_eq!(&packet.as_ref()[26..28], &[0, 0]);
            assert_eq!(&packet.as_ref()[28..], &[value; 80]);
            delivered.push(facts.tuple.source_port);
        }
    }
    delivered.sort_unstable();
    assert_eq!(delivered, [53, 2000]);
    drop(datagrams);
    let returned = later + Duration::from_secs(1);
    table.expire(returned);
    table.expire(returned + IPV4_ID_LIFETIME - Duration::from_nanos(1));
    assert_eq!(table.native_history.len(), 1);
    let reclaimed = returned + IPV4_ID_LIFETIME;
    let mut fresh = fragmentable_udp(
        tuple("198.51.100.9:2001", "203.0.113.5:8080", wire::PROTO_UDP),
        0,
        b"reclaimed",
    );
    let binding = table
        .admit(Admission {
            ingress: ingress(2),
            reply_ingress: ingress(1),
            facts: &Facts::parse(&fresh).unwrap(),
            dnat: Some(DestinationNat {
                address: "10.0.0.2".parse().unwrap(),
                port: Some(1000),
            }),
            snat: SourceNat::None,
            egress: None,
            received_at: reclaimed,
            now: reclaimed,
        })
        .unwrap();
    binding.rewrite(&mut fresh, false).unwrap();
    assert_eq!(u16::from_be_bytes(fresh[4..6].try_into().unwrap()), 0);
    assert_eq!(Facts::parse(&fresh).unwrap().tuple, binding.after_route());
    assert!(table.native_history.is_empty());
}
