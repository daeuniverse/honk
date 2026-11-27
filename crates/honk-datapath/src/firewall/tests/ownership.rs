use super::*;
#[test]
fn core_output_lease_pins_translation_until_resource_return() {
    use crate::forward::{CoreForward, ForwardError, Prepared, Route};
    let now = Instant::now();
    let budget = MemoryBudget::new(16 * 1024 * 1024);
    let mut core = CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
    let mut table = Firewall::new(budget, 8, 1).unwrap();
    let original = tuple("10.0.0.2:1234", "192.0.2.9:53", 17);
    let mut packet = core
        .receive(ingress(1), now, &fragmentable_udp(original, 7, b"proof"))
        .unwrap()
        .unwrap();
    let facts = Facts::from_packet(&packet).unwrap();
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
    let translated = binding.after_route();
    packet
        .rewrite(|bytes| {
            binding
                .rewrite(bytes, false)
                .map_err(|_| ForwardError::Provenance)
        })
        .unwrap();
    packet.bind(binding);
    let route = Route {
        generation: 1,
        ifindex: 2,
        mtu: 1500,
        next_hop: original.destination,
        l2: crate::forward::LinkPath::untagged(2),
        preferred_source: None,
        source_mac: [2, 0, 0, 0, 0, 1],
        destination_mac: [2, 0, 0, 0, 0, 2],
    };
    let Prepared::Forward(mut output) = core.prepare(packet, route, 1, now).unwrap() else {
        panic!("unexpected transit refusal")
    };
    let mut wire = [0; 1500];
    let (length, returned_only_at_cq) = output.write_next(&mut wire).unwrap();
    assert_eq!(Facts::parse(&wire[..length]).unwrap().tuple, translated);
    assert_eq!(wire[8], 63);
    drop(output);
    table.revoke(2);
    table.expire(now);
    let returned = now + 2 * IPV4_ID_LIFETIME;
    table.expire(returned);
    let competitor = Facts::parse(&fragmentable_udp(
        tuple("10.0.0.3:1235", "192.0.2.10:53", wire::PROTO_UDP),
        7,
        b"competitor",
    ))
    .unwrap();
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &competitor,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: returned,
            now: returned,
        }),
        Err(FirewallError::Exhausted)
    ));
    assert_eq!(
        table.entries.len(),
        1,
        "a CQ-held lease outlives a whole MDL"
    );
    assert_eq!(table.identities.len(), 1);
    assert_eq!(table.identities[0].retired_at, None);
    drop(returned_only_at_cq);
    table.expire(returned);
    assert_eq!(
        table.entries.len(),
        1,
        "CQ return starts rather than ends the ID quarantine"
    );
    table.expire(returned + IPV4_ID_LIFETIME - Duration::from_nanos(1));
    assert_eq!(table.identities.len(), 1);
    table.expire(returned + IPV4_ID_LIFETIME);
    assert!(table.entries.is_empty());
}

#[test]
fn materialized_error_keeps_its_grant_without_retaining_the_input_buffer() {
    use crate::forward::CoreForward;
    let now = Instant::now();
    let budget = MemoryBudget::new(16 << 20);
    let mut core = CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
    let mut table = Firewall::new(Arc::clone(&budget), 8, 1).unwrap();
    let input = udp(tuple("10.0.0.2:1234", "192.0.2.9:53", 17));
    let mut packet = core.receive(ingress(1), now, &input).unwrap().unwrap();
    let binding = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &Facts::from_packet(&packet).unwrap(),
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    packet.bind(binding);
    let mut output = [0; 576];
    let length = core
        .error(
            now,
            honk_netstack::transit::TransitError::AdminProhibited,
            "192.0.2.254".parse().unwrap(),
            &packet,
            &mut output,
        )
        .unwrap()
        .unwrap();
    assert_eq!(&output[28..length], input.as_slice());
    let device_grant = packet.into_binding().unwrap();
    table.revoke(2);
    table.expire(now);
    assert!(!table.is_empty());
    drop(device_grant);
    table.expire(now);
    assert!(table.is_empty());
    drop(table);
    drop(core);
    assert_eq!(budget.used(), 0);
}

#[test]
fn queued_batch_uses_receive_floor_and_processing_expiration() {
    use crate::forward::CoreForward;
    let received_at = Instant::now();
    let processed_at = received_at + Duration::from_secs(5);
    let budget = MemoryBudget::new(16 * 1024 * 1024);
    let mut core = CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
    let mut table = Firewall::new(budget, 8, 1).unwrap();
    let original = tuple("10.0.0.2:1234", "192.0.2.9:53", 17);
    let first = core
        .receive(ingress(1), received_at, &udp(original))
        .unwrap()
        .unwrap();
    let mut queued = core
        .receive(ingress(1), received_at, &udp(original))
        .unwrap()
        .unwrap();
    let future = processed_at + Duration::from_nanos(1);
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &Facts::from_packet(&first).unwrap(),
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: future,
            now: processed_at
        }),
        Err(FirewallError::Denied)
    ));
    assert!(table.is_empty());
    let lease = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &Facts::from_packet(&first).unwrap(),
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: first.received_at(),
            now: processed_at,
        })
        .unwrap();
    let facts = Facts::from_packet(&queued).unwrap();
    assert!(matches!(
        table.lookup(ingress(1), &facts, received_at - Duration::from_nanos(1)),
        Err(FirewallError::Denied)
    ));
    let binding = table
        .lookup(ingress(1), &facts, queued.received_at())
        .unwrap()
        .unwrap();
    queued
        .rewrite(|bytes| {
            binding
                .rewrite(bytes, false)
                .map_err(|_| crate::forward::ForwardError::Provenance)
        })
        .unwrap();
    assert_eq!(
        Facts::from_packet(&queued).unwrap().tuple,
        lease.after_route()
    );
    table.expire(received_at + Duration::from_secs(119));
    assert!(lease.is_active());
    table.expire(received_at + Duration::from_secs(120));
    assert!(!lease.is_active());
    let mut bounded = Firewall::new(MemoryBudget::new(1024 * 1024), 1, 1).unwrap();
    drop(
        bounded
            .admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &facts,
                dnat: None,
                snat: snat(),
                egress: None,
                received_at,
                now: received_at,
            })
            .unwrap(),
    );
    let next = Facts::parse(&udp(tuple("10.0.0.3:1235", "192.0.2.10:53", 17))).unwrap();
    let later_receive = received_at + Duration::from_secs(119);
    assert!(
        bounded
            .admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &next,
                dnat: None,
                snat: snat(),
                egress: None,
                received_at: later_receive,
                now: received_at + Duration::from_secs(120)
            })
            .is_ok()
    );
}

#[test]
fn exhaustion_revocation_and_held_outputs_are_atomic() {
    let now = Instant::now();
    let mut table = table();
    let first = Facts::parse(&udp(tuple("10.0.0.2:1000", "192.0.2.9:53", 17))).unwrap();
    let second = Facts::parse(&udp(tuple("10.0.0.3:1001", "192.0.2.10:53", 17))).unwrap();
    let lease = table
        .admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &first,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now,
        })
        .unwrap();
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &second,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now
        }),
        Err(FirewallError::Exhausted)
    ));
    assert_eq!(table.entries.len(), 1);
    table.revoke(2);
    table.expire(now + Duration::from_secs(1000));
    assert!(!lease.is_current(2));
    assert_eq!(table.entries.len(), 1);
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &second,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now
        }),
        Err(FirewallError::Exhausted)
    ));
    table.set_fragment_obligations(std::iter::once(obligation(ingress(1), first.tuple)));
    drop(lease);
    table.expire(now);
    assert!(matches!(
        table.admit(Admission {
            ingress: ingress(1),
            reply_ingress: ingress(2),
            facts: &second,
            dnat: None,
            snat: snat(),
            egress: None,
            received_at: now,
            now
        }),
        Err(FirewallError::Exhausted)
    ));
    table.set_fragment_obligations(std::iter::empty());
    table.expire(now);
    assert!(
        table
            .admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &second,
                dnat: None,
                snat: snat(),
                egress: None,
                received_at: now,
                now
            })
            .is_ok()
    );
}
#[test]
fn fragment_obligations_do_not_freeze_unrelated_bindings_or_restart_their_mdl() {
    let now = Instant::now();
    let mut table = table();
    let first = tuple("10.0.0.2:1000", "192.0.2.9:53", wire::PROTO_UDP);
    let second = tuple("10.0.0.3:1001", "192.0.2.10:53", wire::PROTO_UDP);
    let action = SourceNat::Snat {
        address: "198.51.100.1".parse().unwrap(),
        ports: Some(PortPool {
            first: 40000,
            last: 40001,
        }),
    };
    for original in [first, second] {
        drop(
            table
                .admit(Admission {
                    ingress: ingress(1),
                    reply_ingress: ingress(2),
                    facts: &Facts::parse(&fragmentable_udp(original, 7, b"proof")).unwrap(),
                    dnat: None,
                    snat: action,
                    egress: None,
                    received_at: now,
                    now,
                })
                .unwrap(),
        );
    }
    table.revoke(2);
    table.expire(now);
    for seconds in (10..=130).step_by(20) {
        table.set_fragment_obligations(std::iter::once(obligation(ingress(1), first)));
        table.expire(now + Duration::from_secs(seconds));
        if seconds < 120 {
            assert_eq!(table.identities[1].retired_at, Some(now));
        }
    }
    assert_eq!(table.identities.len(), 1);
    assert_eq!(
        table.identities[0]
            .identity
            .binding
            .as_ref()
            .unwrap()
            .original,
        first
    );
    assert_eq!(table.entries.len(), 1);
    table.set_fragment_obligations(std::iter::once(obligation(ingress(3), first)));
    let retired = now + Duration::from_secs(130);
    table.expire(retired);
    table.expire(retired + IPV4_ID_LIFETIME);
    assert!(table.identities.is_empty());
    assert!(table.entries.is_empty());
}

#[test]
fn revoked_grant_denies_lookup_rewrite_and_prepared_output() {
    use crate::forward::{CoreForward, ForwardError, LinkPath, Prepared, Route};
    let now = Instant::now();
    let budget = MemoryBudget::new(16 << 20);
    let mut core = CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
    let mut table = Firewall::new(budget, 8, 1).unwrap();
    let original = tuple("10.0.0.2:1234", "192.0.2.9:53", wire::PROTO_UDP);
    let input = udp(original);
    let facts = Facts::parse(&input).unwrap();
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
    let route = Route {
        generation: 1,
        ifindex: 2,
        mtu: 1500,
        next_hop: original.destination,
        l2: LinkPath::untagged(2),
        preferred_source: None,
        source_mac: [2, 0, 0, 0, 0, 1],
        destination_mac: [2, 0, 0, 0, 0, 2],
    };
    let mut packet = core.receive(ingress(1), now, &input).unwrap().unwrap();
    packet.bind(binding.clone());
    let Prepared::Forward(mut prepared) = core.prepare(packet, route, 1, now).unwrap() else {
        panic!("unexpected transit refusal");
    };
    let mut packet = core.receive(ingress(1), now, &input).unwrap().unwrap();
    packet.bind(binding.clone());
    table.revoke(2);
    assert!(!binding.is_current(1));
    assert!(!binding.is_current(2));
    assert!(matches!(
        table.lookup(ingress(1), &facts, now),
        Err(FirewallError::Stale)
    ));
    assert!(matches!(
        binding.rewrite(&mut input.clone(), false),
        Err(FirewallError::Stale)
    ));
    assert!(!packet.is_current(now));
    assert!(matches!(
        core.prepare(packet, route, 1, now),
        Err(ForwardError::Expired)
    ));
    let mut output = [0xa5; 1500];
    assert!(prepared.write_next(&mut output).is_none());
    assert!(output.iter().all(|byte| *byte == 0xa5));
}

#[test]
fn receive_pin_does_not_allocate_identity_or_renew_authority() {
    let now = Instant::now();
    let mut table = table();
    let facts = Facts::parse(&fragmentable_udp(
        tuple("10.0.0.2:1234", "192.0.2.9:53", wire::PROTO_UDP),
        7,
        b"proof",
    ))
    .unwrap();
    drop(
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
            .unwrap(),
    );
    let later = now + Duration::from_secs(1);
    for _ in 0..table.identity_capacity {
        let pin = table.pin(ingress(1), &facts, later).unwrap().unwrap();
        assert!(!pin.is_authorized());
        assert!(pin.identity.is_none());
        assert!(matches!(
            pin.rewrite(&mut udp(facts.tuple), false),
            Err(FirewallError::Stale)
        ));
    }
    assert_eq!(table.entries[0].last, now);
    assert_eq!(table.identities.len(), 1);
    let admitted = table.lookup(ingress(1), &facts, later).unwrap().unwrap();
    assert!(admitted.is_authorized());
    assert_eq!(table.entries[0].last, later);
    assert_eq!(table.identities.len(), 2);
}

#[test]
fn timeout_quote_retention_respects_suppression_and_matching_output_domains() {
    use crate::forward::CoreForward;
    for icmp_error in [false, true] {
        let now = Instant::now();
        let budget = MemoryBudget::new(16 << 20);
        let mut core = CoreForward::new(&[ingress(1), ingress(2)], Arc::clone(&budget), 8).unwrap();
        let mut table = Firewall::new(budget, 8, 1).unwrap();
        let first = tuple("10.0.0.2:1000", "192.0.2.9:53", wire::PROTO_UDP);
        let second = tuple("10.0.0.3:1001", "192.0.2.10:53", wire::PROTO_UDP);
        let mut translated = Vec::new();
        let mut reply = first.reverse();
        for (original, address) in [(first, "198.51.100.1"), (second, "198.51.100.2")] {
            let mut bytes = fragmentable_udp(original, 7, &[0x11; 80]);
            let lease = table
                .admit(Admission {
                    ingress: ingress(1),
                    reply_ingress: ingress(2),
                    facts: &Facts::parse(&bytes).unwrap(),
                    dnat: None,
                    snat: SourceNat::Snat {
                        address: address.parse().unwrap(),
                        ports: None,
                    },
                    egress: None,
                    received_at: now,
                    now,
                })
                .unwrap();
            lease.rewrite(&mut bytes, false).unwrap();
            if original == first {
                reply = lease.after_route().reverse();
                translated = bytes;
            }
        }
        let input = if icmp_error {
            quoted_error(&translated)
        } else {
            fragmentable_udp(reply, 0x99, &[0x77; 80])
        };
        let mut first_fragment = input[..36].to_vec();
        first_fragment[2..4].copy_from_slice(&36u16.to_be_bytes());
        first_fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        seal_ipv4(&mut first_fragment);
        assert!(
            core.receive(ingress(2), now, &first_fragment)
                .unwrap()
                .is_none()
        );
        table.set_fragment_obligations(core.fragment_obligations());
        table.revoke(2);
        table.expire(now);
        let timeout = now + honk_netstack::FragmentLimits::default().timeout;
        core.retire(timeout);
        let (input_ingress, quote) = core.poll_expired_quote().unwrap();
        let metadata = honk_netstack::transit::quote_metadata(&quote);
        let mut wire = [0; 1280];
        let generated = core
            .reassembly_error(
                input_ingress,
                timeout,
                "198.51.100.254".parse().unwrap(),
                &quote,
                &mut wire,
            )
            .unwrap();
        if icmp_error {
            assert!(metadata.is_none());
            assert!(
                generated.is_none(),
                "an ICMP error timeout must not originate another error"
            );
            table.set_fragment_obligations(core.fragment_obligations());
            table.expire(timeout);
            table.expire(now + IPV4_ID_LIFETIME);
            assert_eq!(table.identities.len(), 1);
            let competitor = Facts::parse(&fragmentable_udp(
                tuple("10.0.0.4:4000", "192.0.2.11:53", wire::PROTO_UDP),
                7,
                b"competitor",
            ))
            .unwrap();
            let action = SourceNat::Snat {
                address: "198.51.100.1".parse().unwrap(),
                ports: Some(PortPool {
                    first: 1000,
                    last: 1000,
                }),
            };
            let before = timeout + IPV4_ID_LIFETIME - Duration::from_nanos(1);
            assert!(matches!(
                table.admit(Admission {
                    ingress: ingress(1),
                    reply_ingress: ingress(2),
                    facts: &competitor,
                    dnat: None,
                    snat: action,
                    egress: None,
                    received_at: before,
                    now: before,
                }),
                Err(FirewallError::Exhausted)
            ));
            let reclaimed = timeout + IPV4_ID_LIFETIME;
            let lease = table
                .admit(Admission {
                    ingress: ingress(1),
                    reply_ingress: ingress(2),
                    facts: &competitor,
                    dnat: None,
                    snat: action,
                    egress: None,
                    received_at: reclaimed,
                    now: reclaimed,
                })
                .unwrap();
            let mut packet = fragmentable_udp(competitor.tuple, 7, b"competitor");
            lease.rewrite(&mut packet, false).unwrap();
            assert_eq!(Facts::parse(&packet).unwrap().tuple, lease.after_route());
            assert_eq!(lease.after_route().source_port, 1000);
            continue;
        }
        let metadata = metadata.unwrap();
        assert_eq!(metadata.protocol, wire::PROTO_UDP);
        assert_eq!(
            metadata.ports,
            Some((reply.source_port, reply.destination_port))
        );
        let generated = generated.unwrap();
        assert!(Facts::parse(&wire[..generated]).is_ok());
        assert_eq!(&wire[20..22], &[11, 1]);
        let exported = table
            .retain_fragment(FragmentObligation {
                ingress: input_ingress,
                source: metadata.source,
                destination: metadata.destination,
                protocol: metadata.protocol,
            })
            .unwrap()
            .unwrap();
        let cq_copy = exported.clone();
        drop(quote);
        table.set_fragment_obligations(core.fragment_obligations());
        table.expire(timeout);
        table.expire(timeout + 2 * IPV4_ID_LIFETIME);
        assert_eq!(table.identities.len(), 1);
        assert_eq!(
            table.identities[0]
                .identity
                .binding
                .as_ref()
                .unwrap()
                .original,
            first
        );
        drop(exported);
        let returned = timeout + 3 * IPV4_ID_LIFETIME;
        table.expire(returned);
        assert_eq!(table.identities.len(), 1);
        drop(cq_copy);
        table.expire(returned);
        table.expire(returned + IPV4_ID_LIFETIME - Duration::from_nanos(1));
        assert_eq!(table.identities.len(), 1);
        table.expire(returned + IPV4_ID_LIFETIME);
        assert!(table.is_empty());
    }
}

#[test]
fn unrelated_icmp_receive_pin_does_not_infer_authority_or_refuse_plain_routing() {
    let now = Instant::now();
    let mut table = table();
    let admitted = udp(tuple("10.0.0.2:1000", "192.0.2.9:53", wire::PROTO_UDP));
    drop(
        table
            .admit(Admission {
                ingress: ingress(1),
                reply_ingress: ingress(2),
                facts: &Facts::parse(&admitted).unwrap(),
                dnat: None,
                snat: snat(),
                egress: None,
                received_at: now,
                now,
            })
            .unwrap(),
    );
    let quote = udp(tuple("10.0.0.3:2000", "192.0.2.10:53", wire::PROTO_UDP));
    let error = quoted_error(&quote);
    let facts = Facts::parse(&error).unwrap();
    assert!(table.pin(ingress(2), &facts, now).unwrap().is_none());
    assert!(matches!(
        table.lookup(ingress(2), &facts, now),
        Err(FirewallError::Denied)
    ));
    assert_eq!(table.entries.len(), 1);
    assert!(table.identities.is_empty());
}
