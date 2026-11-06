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
            Push::Pending | Push::Dropped(_)
        ));
        now += Duration::from_secs(30);
        r.expire(now);
        assert!(!r.expired.is_empty());
        for quote in &r.expired {
            assert!(quote.len() <= crate::icmp_out::quote_limit(true));
            assert_eq!(quote.capacity(), quote.len());
        }
        let retained: usize = r.expired.iter().map(Vec::capacity).sum();
        assert_eq!(budget.used(), retained);
        assert!(budget.used() <= budget.limit());
        r.check();
    }
    assert!(budget.used() > 0);
    let mut icmp = IcmpOut::default();
    assert!(matches!(
        r.poll_icmp(now, &mut icmp, &mut [0; 1500]),
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
        let expected = r.expired.front().unwrap().clone();
        let charged = r.expired.front().unwrap().capacity();
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
            let retained: usize = r.expired.iter().map(Vec::capacity).sum();
            assert_eq!(budget.used(), retained);
            assert!(retained > 0);
            let mut icmp = IcmpOut::new(crate::IcmpLimits {
                burst,
                ..crate::IcmpLimits::default()
            });
            assert!(matches!(
                r.poll_icmp(late, &mut icmp, &mut [0; 1]),
                Output::Blocked
            ));
            assert_eq!(budget.used(), retained);
            let result = r.poll_icmp(late, &mut icmp, &mut [0; 1500]);
            if burst == 1 {
                assert!(matches!(result, Output::Sent(_)));
                assert!(budget.used() < retained && budget.used() > 0);
                assert!(matches!(
                    r.poll_icmp(late, &mut icmp, &mut [0; 1500]),
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
        r.poll_icmp(late, &mut icmp, &mut [0; 1500]),
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
