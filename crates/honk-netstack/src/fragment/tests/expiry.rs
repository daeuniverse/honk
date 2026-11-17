use super::*;

#[test]
fn large_expiry_quotes_are_truncated_and_stay_within_the_shared_budget() {
    let budget = MemoryBudget::new(20 * 1024);
    let mut r = Reassembler::default().with_budget(Some(budget.clone()));
    let mut now = Instant::now();
    let mut packet = vec![0; 40 + 8 * 2048 + 8 + 8];
    let payload_len = packet.len() - 40;
    ipv6::emit(
        &mut packet,
        "fd00::2".parse().unwrap(),
        "fd00::7".parse().unwrap(),
        60,
        payload_len,
    )
    .unwrap();
    for i in 0..8 {
        let off = 40 + i * 2048;
        packet[off] = if i == 7 { 44 } else { 60 };
        packet[off + 1] = 255;
    }
    let frag = 40 + 8 * 2048;
    for id in 0..20 {
        ipv6::emit_fragment_header(&mut packet[frag..], wire::PROTO_UDP, 0, true, id).unwrap();
        assert!(matches!(
            push(&mut r, now, &packet),
            Push::Pending(_) | Push::Dropped(_)
        ));
        now += Duration::from_secs(30);
        r.expire(now);
        assert!(!r.expired.is_empty());
        for quote in &r.expired {
            assert!(quote.bytes.len() <= crate::icmp_out::quote_limit(true));
            assert_eq!(quote.bytes.capacity(), quote.bytes.len());
        }
        let retained: usize = r.expired.iter().map(|quote| quote.bytes.capacity()).sum();
        assert_eq!(budget.used(), retained);
        assert!(budget.used() <= budget.limit());
        r.check();
    }
    assert!(budget.used() > 0);
    let mut icmp = IcmpOut::default();
    assert!(matches!(
        r.poll_icmp(now, &mut icmp, &mut [0; 1500], &mut Transmit::plain(0)),
        Output::None
    ));
    assert!(
        icmp.suppressed > 0,
        "the truncated extension chain is uninspectable"
    );
    r.assert_idle();
    assert_eq!(budget.used(), 0);
}

#[test]
fn expired_quotes_transfer_their_charge_with_no_budget_headroom() {
    for (src, dst) in families() {
        let budget = MemoryBudget::new(20 * 1024);
        let mut r = Reassembler::default()
            .for_transit()
            .with_budget(Some(Arc::clone(&budget)));
        let now = Instant::now();
        let late = now + Duration::from_secs(30);
        let original = datagram(src, dst, 1000, 1);
        for id in 0..2 {
            let packets = split(&original, id, 400);
            pending(push(&mut r, now, &packets[0]));
        }
        r.expire(late);
        let packets = split(&original, 2, 400);
        pending(push(&mut r, late, &packets[0]));
        assert_eq!(r.expired.len(), 2);
        let expected = r.expired.front().unwrap().bytes.clone();
        let charged = r.expired.front().unwrap().bytes.capacity();
        assert_eq!(charged, expected.len());
        let retained = r.bytes() - charged;
        let other = budget.reserve(budget.limit() - budget.used()).unwrap();
        assert_eq!(budget.used(), budget.limit());

        let quote = r
            .take_expired()
            .expect("the queued quote is already funded");
        assert_eq!(quote.as_ref(), expected.as_slice());
        assert!(quote.charged_to(&budget));
        assert_eq!(quote.ipv6_fragment(), None);
        assert_eq!(quote._reservation.as_ref().unwrap().bytes(), charged);
        assert_eq!(budget.used(), budget.limit());
        assert_eq!(r.bytes(), retained);
        r.check();
        let quote = Arc::new(quote);
        let final_owner = Arc::clone(&quote);
        drop(r);
        assert_eq!(budget.used(), other.bytes() + charged);
        drop(other);
        assert_eq!(budget.used(), charged);
        drop(quote);
        assert_eq!(budget.used(), charged);
        drop(final_owner);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn expiry_quotes_remain_funded_through_blocked_sent_and_rate_limited_output() {
    for (src, dst) in families() {
        for burst in [0, 1] {
            let budget = MemoryBudget::new(20 * 1024);
            let mut r = Reassembler::default().with_budget(Some(budget.clone()));
            let now = Instant::now();
            let late = now + Duration::from_secs(30);
            for id in 0..17 {
                let packets = split(&datagram(src, dst, 1000, 1), id, 400);
                pending(push(&mut r, now, &packets[0]));
                r.expire(late);
            }
            assert_eq!(r.expired.len(), MAX_PENDING_ICMP);
            let retained: usize = r.expired.iter().map(|quote| quote.bytes.capacity()).sum();
            assert_eq!(budget.used(), retained);
            assert!(retained > 0);
            let mut icmp = IcmpOut::new(crate::IcmpLimits {
                burst,
                ..crate::IcmpLimits::default()
            });
            assert!(matches!(
                r.poll_icmp(late, &mut icmp, &mut [0; 1], &mut Transmit::plain(0)),
                Output::Blocked
            ));
            assert_eq!(budget.used(), retained);
            let result = r.poll_icmp(late, &mut icmp, &mut [0; 1500], &mut Transmit::plain(0));
            if burst == 1 {
                assert!(matches!(result, Output::Sent(_)));
                assert!(budget.used() < retained && budget.used() > 0);
                assert!(matches!(
                    r.poll_icmp(late, &mut icmp, &mut [0; 1500], &mut Transmit::plain(0)),
                    Output::None
                ));
            } else {
                assert!(matches!(result, Output::None));
            }
            assert!(icmp.rate_limited > 0);
            r.assert_idle();
            assert_eq!(budget.used(), 0);
            let packets = split(&datagram(src, dst, 1000, 1), 99, 400);
            pending(push(&mut r, now, &packets[0]));
            r.expire(late);
            assert!(budget.used() > 0);
            drop(r);
            assert_eq!(budget.used(), 0);
        }
    }
}

#[test]
fn expiry_never_answers_icmpv6_behind_fragment_and_destination_options() {
    let now = Instant::now();
    let budget = MemoryBudget::new(20 * 1024);
    let mut r = Reassembler::default().with_budget(Some(budget.clone()));
    let mut packet = vec![0; 64];
    ipv6::emit(
        &mut packet,
        "fd00::2".parse().unwrap(),
        "fd00::7".parse().unwrap(),
        44,
        24,
    )
    .unwrap();
    ipv6::emit_fragment_header(&mut packet[40..], 60, 0, true, 1).unwrap();
    packet[48] = wire::PROTO_ICMPV6;
    packet[56] = 1;
    pending(push(&mut r, now, &packet));
    let late = now + Duration::from_secs(30);
    r.expire(late);
    assert!(r.pending_icmp());
    let mut icmp = IcmpOut::default();
    assert!(matches!(
        r.poll_icmp(late, &mut icmp, &mut [0; 1500], &mut Transmit::plain(0)),
        Output::None
    ));
    assert_eq!(icmp.suppressed, 1);
    assert_eq!(budget.used(), 0);
    r.assert_idle();
}

#[test]
fn transit_receive_enforces_the_reassembly_deadline_without_a_timer_poll() {
    let now = Instant::now();
    let limits = FragmentLimits::default();
    let tick = Duration::from_nanos(1);
    for (src, dst) in families() {
        let original = datagram(src, dst, 8, 25);
        let packets = split(&original, 19, 8);
        assert_eq!(packets.len(), 2);
        for first in [0, 1] {
            for delay in [
                limits.timeout - tick,
                limits.timeout,
                limits.timeout + tick,
                limits.timeout * 2,
            ] {
                let budget = MemoryBudget::new(16 << 20);
                let mut transit =
                    crate::transit::Transit::new(Arc::clone(&budget), limits).unwrap();
                let baseline = budget.used();
                assert!(transit.reassemble(now, &packets[first]).unwrap().is_none());
                assert_eq!(transit.poll_timeout(), Some(now + limits.timeout));
                let arrival = now + delay;
                let received = transit.reassemble(arrival, &packets[1 - first]).unwrap();
                let packet = if delay < limits.timeout {
                    assert!(transit.poll_expired_quote().is_none());
                    received.expect("the old assembly is live just before its deadline")
                } else {
                    assert!(received.is_none(), "the expired assembly cannot complete");
                    assert_eq!(transit.poll_timeout(), Some(arrival + limits.timeout));
                    assert_eq!(
                        transit.fragment_obligations().count(),
                        1 + usize::from(first == 0)
                    );
                    let retained = budget.used();
                    let quote = transit.poll_expired_quote();
                    if first == 0 {
                        let quote = quote.expect("expiry retains the original fragment-zero quote");
                        assert_eq!(quote.as_ref(), packets[0].as_slice());
                        let quote_len = quote.len();
                        assert!(quote.charged_to(&budget));
                        assert_eq!(budget.used(), retained);
                        drop(quote);
                        assert_eq!(budget.used(), retained - quote_len);
                    } else {
                        assert!(
                            quote.is_none(),
                            "a non-first fragment cannot originate a quote"
                        );
                    }
                    assert_eq!(transit.fragment_obligations().count(), 1);
                    transit
                        .reassemble(arrival + tick, &packets[first])
                        .unwrap()
                        .expect(
                            "the arriving fragment can begin a new independently timed assembly",
                        )
                };
                let ip = wire::PacketView::from_slice(&packet)
                    .validate_transport()
                    .unwrap();
                let original_ip = wire::parse_ip(&original).unwrap();
                assert_eq!(&packet[ip.payload], &original[original_ip.payload]);
                assert!(transit.is_quiescent());
                assert_eq!(transit.fragment_obligations().count(), 0);
                assert_eq!(transit.poll_timeout(), None);
                assert!(transit.poll_expired_quote().is_none());
                assert_eq!(budget.used(), baseline + packet.len());
                drop(packet);
                assert_eq!(budget.used(), baseline);
                drop(transit);
                assert_eq!(budget.used(), 0);
            }
        }
    }
}

#[test]
fn handoff_uses_the_minimum_original_ingress_before_completing_or_expiring() {
    let now = Instant::now();
    let limits = FragmentLimits::default();
    for (src, dst) in families() {
        let original = datagram(src, dst, 8, 27);
        let packets = split(&original, 21, 8);
        for first in [0, 1] {
            for expired in [false, true] {
                let budget = MemoryBudget::new(16 << 20);
                let mut transit =
                    crate::transit::Transit::new(Arc::clone(&budget), limits).unwrap();
                let baseline = budget.used();
                let later_ingress = now + Duration::from_secs(10);
                assert!(
                    transit
                        .reassemble_at(later_ingress, later_ingress, &packets[first])
                        .unwrap()
                        .is_none()
                );
                let service = now + limits.timeout - Duration::from_nanos(u64::from(!expired));
                let result = transit.reassemble_at(now, service, &packets[1 - first]);
                if expired {
                    assert_eq!(result.unwrap_err(), DropReason::Fragment);
                    assert_eq!(transit.poll_timeout(), None);
                    let quote = transit.poll_expired_quote();
                    assert_eq!(quote.is_some(), first == 0);
                    if let Some(quote) = quote {
                        assert!(quote.charged_to(&budget));
                        assert_eq!(quote.fragment_info().original_ingress, now);
                        assert_eq!(quote.as_ref(), packets[0].as_slice());
                    }
                } else {
                    let packet = result
                        .unwrap()
                        .expect("not expired before original deadline");
                    assert!(packet.charged_to(&budget));
                    assert_eq!(packet.fragment_info().original_ingress, now);
                    assert_eq!(packet.completion_ingress(), later_ingress);
                    let ip = wire::parse_ip(&packet).unwrap();
                    let original_ip = wire::parse_ip(&original).unwrap();
                    assert_eq!(&packet[ip.payload], &original[original_ip.payload]);
                }
                assert!(transit.is_quiescent());
                assert_eq!(budget.used(), baseline);
                drop(transit);
                assert_eq!(budget.used(), 0);
            }
        }
    }
}

#[test]
fn earlier_original_ingress_shortens_tombstones_without_losing_the_source() {
    let now = Instant::now();
    let source = SourceContext {
        lineage: NonZeroU64::new(7).unwrap(),
        snapshot: NonZeroU64::new(9).unwrap(),
    };
    for (src, dst) in families() {
        let packet = datagram(src, dst, 8, 28);
        let fragments = split(&packet, 22, 8);
        let mut reasm = Reassembler::default();
        let later = now + Duration::from_secs(10);
        pending(reasm.push_at(
            later,
            later,
            frag::parse(&fragments[0]).unwrap(),
            Some(source),
        ));
        assert!(matches!(
            reasm.push_at(
                later,
                later,
                frag::parse(&fragments[0]).unwrap(),
                Some(source)
            ),
            Push::Dropped(DropReason::Fragment)
        ));
        assert!(matches!(
            reasm.push_at(
                now,
                later,
                frag::parse(&fragments[1]).unwrap(),
                Some(source)
            ),
            Push::Dropped(DropReason::Fragment)
        ));
        assert_eq!(reasm.poll_timeout(), Some(now + reasm.limits.timeout));
        let mut retained = Vec::new();
        reasm.visit_retained_source_contexts(|context| retained.push(context));
        assert_eq!(retained, [source]);
        assert_eq!(reasm.bytes(), ENTRY_OVERHEAD);
        reasm.expire(now + reasm.limits.timeout);
        reasm.check();
        reasm.assert_idle();
    }
}

#[test]
fn fragment_error_receipt_preserves_earlier_ingress_on_overlap_and_timeout() {
    let now = Instant::now();
    for (src, dst) in families() {
        let packets = split(&datagram(src, dst, 8, 31), 41, 8);
        for overlap in [false, true] {
            let budget = MemoryBudget::new(32 << 10);
            let mut reasm = Reassembler::default().with_budget(Some(Arc::clone(&budget)));
            let later = now + Duration::from_secs(10);
            let original = reasm
                .push_for_dispatch_at(later, later, frag::parse(&packets[0]).unwrap())
                .unwrap()
                .fragment;
            let (packet, service) = if overlap {
                (&packets[0], now + Duration::from_secs(15))
            } else {
                (&packets[1], now + Duration::from_secs(30))
            };
            let rejected = reasm
                .push_for_dispatch_at(now, service, frag::parse(packet).unwrap())
                .unwrap_err();
            assert_eq!(rejected.reason, DropReason::Fragment);
            let updated = rejected
                .fragment
                .expect("matched assembly retains its exact receipt");
            assert_eq!(updated.identity, original.identity);
            assert_eq!(updated.original_ingress, now);
            assert_eq!(updated.incarnation, original.incarnation);
            assert!(reasm.retains_fragment(original));
            assert!(reasm.retains_fragment(updated));
            if overlap {
                assert_eq!(reasm.bytes(), ENTRY_OVERHEAD);
                reasm.expire(now + Duration::from_secs(30));
            } else {
                let quote = reasm.take_expired().unwrap();
                assert_eq!(quote.fragment_info(), updated);
                assert_eq!(quote.as_ref(), packets[0].as_slice());
                assert!(!reasm.retains_fragment(updated));
                drop(quote);
            }
            reasm.assert_idle();
            assert_eq!(budget.used(), 0);
        }
    }
}

#[test]
fn fragment_incarnations_distinguish_identical_key_and_minimum_quotes() {
    let now = Instant::now();
    for (src, dst) in families() {
        let budget = MemoryBudget::new(64 << 10);
        let mut reasm = Reassembler::default().with_budget(Some(Arc::clone(&budget)));
        let packets = split(&datagram(src, dst, 8, 33), 51, 8);
        let old = reasm
            .push_for_dispatch_at(now, now, frag::parse(&packets[0]).unwrap())
            .unwrap()
            .fragment;
        reasm.expire(now + Duration::from_secs(30));
        let fresh = reasm
            .push_for_dispatch_at(
                now + Duration::from_secs(10),
                now + Duration::from_secs(30),
                frag::parse(&packets[0]).unwrap(),
            )
            .unwrap()
            .fragment;
        assert_ne!(old.incarnation, fresh.incarnation);
        let rejected = reasm
            .push_for_dispatch_at(
                now,
                now + Duration::from_secs(35),
                frag::parse(&packets[1]).unwrap(),
            )
            .unwrap_err();
        let shortened = rejected.fragment.unwrap();
        assert_eq!(shortened.identity, old.identity);
        assert_eq!(shortened.original_ingress, old.original_ingress);
        assert_eq!(shortened.incarnation, fresh.incarnation);
        assert!(reasm.retains_fragment(old));
        assert!(reasm.retains_fragment(fresh));
        let old_quote = reasm.take_expired().unwrap();
        let fresh_quote = reasm.take_expired().unwrap();
        assert_eq!(old_quote.fragment_info(), old);
        assert_eq!(fresh_quote.fragment_info(), shortened);
        assert!(!reasm.retains_fragment(old));
        assert!(!reasm.retains_fragment(fresh));
        let stale = reasm
            .push_for_dispatch_at(
                now,
                now + Duration::from_secs(35),
                frag::parse(&packets[0]).unwrap(),
            )
            .unwrap_err();
        assert_eq!(stale.reason, DropReason::Fragment);
        assert_eq!(stale.fragment, None);
        assert_eq!(reasm.len(), 0);
        let next = reasm
            .push_for_dispatch_at(
                now + Duration::from_secs(11),
                now + Duration::from_secs(35),
                frag::parse(&packets[0]).unwrap(),
            )
            .unwrap()
            .fragment;
        assert_ne!(next.incarnation, old.incarnation);
        assert_ne!(next.incarnation, fresh.incarnation);
        let complete = reasm
            .push_for_dispatch_at(
                now + Duration::from_secs(12),
                now + Duration::from_secs(35),
                frag::parse(&packets[1]).unwrap(),
            )
            .unwrap();
        assert_eq!(complete.fragment, next);
        let complete = complete.packet.unwrap();
        assert_eq!(complete.fragment_info(), next);
        assert!(!reasm.retains_fragment(next));
        reasm.check();
        drop(reasm);
        assert_eq!(
            budget.used(),
            old_quote.len() + fresh_quote.len() + complete.len()
        );
        drop((old_quote, fresh_quote, complete));
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn fragment_incarnation_exhaustion_preserves_existing_and_atomic_progress() {
    let now = Instant::now();
    let budget = MemoryBudget::new(64 << 10);
    let mut reasm = Reassembler::new(FragmentLimits {
        max_entries: 2,
        ..FragmentLimits::default()
    })
    .with_budget(Some(Arc::clone(&budget)));
    let whole = datagram(v6(2), v6(7), 8, 34);
    let packets = split(&whole, 60, 8);
    let other = split(&whole, 61, 8);
    let denied = split(&whole, 62, 8);
    let first = reasm
        .push_for_dispatch_at(now, now, frag::parse(&packets[0]).unwrap())
        .unwrap()
        .fragment;
    let second = reasm
        .push_for_dispatch_at(now, now, frag::parse(&other[0]).unwrap())
        .unwrap()
        .fragment;
    reasm.last_incarnation = u64::MAX;
    let before = (budget.used(), reasm.bytes(), reasm.stats.evicted);
    let error = reasm
        .push_for_dispatch_at(now, now, frag::parse(&denied[0]).unwrap())
        .unwrap_err();
    assert_eq!(error.reason, DropReason::Capacity);
    assert_eq!(error.fragment, None);
    assert_eq!((budget.used(), reasm.bytes(), reasm.stats.evicted), before);
    assert!(reasm.retains_fragment(first));
    assert!(reasm.retains_fragment(second));
    let atomic = split(&whole, 60, 64);
    assert_eq!(atomic.len(), 1);
    let complete = reasm
        .push_for_dispatch_at(now, now, frag::parse(&atomic[0]).unwrap())
        .unwrap();
    assert_eq!(complete.fragment.incarnation, None);
    assert!(!reasm.retains_fragment(complete.fragment));
    assert!(reasm.retains_fragment(first));
    assert_eq!(reasm.last_incarnation, u64::MAX);
    drop(complete);
    let completed = reasm
        .push_for_dispatch_at(now, now, frag::parse(&packets[1]).unwrap())
        .unwrap();
    assert_eq!(completed.fragment.incarnation, first.incarnation);
    let completed = completed.packet.unwrap();
    reasm.expire(now + Duration::from_secs(30));
    let quote = reasm.take_expired().unwrap();
    assert_eq!(quote.fragment_info(), second);
    reasm.assert_idle();
    drop((completed, quote));
    assert_eq!(budget.used(), 0);
}
