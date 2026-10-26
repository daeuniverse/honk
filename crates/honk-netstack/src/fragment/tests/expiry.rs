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
        assert!(matches!(push(&mut r, now, &packet), Push::Pending | Push::Dropped(_)));
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
    assert!(matches!(r.poll_icmp(now, &mut icmp, &mut [0; 1500]), Output::None));
    assert!(icmp.suppressed > 0, "the truncated extension chain is uninspectable");
    r.assert_idle();
    assert_eq!(budget.used(), 0);
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
            assert!(matches!(r.poll_icmp(late, &mut icmp, &mut [0; 1]), Output::Blocked));
            assert_eq!(budget.used(), retained);
            let result = r.poll_icmp(late, &mut icmp, &mut [0; 1500]);
            if burst == 1 {
                assert!(matches!(result, Output::Sent(_)));
                assert!(budget.used() < retained && budget.used() > 0);
                assert!(matches!(r.poll_icmp(late, &mut icmp, &mut [0; 1500]), Output::None));
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
    ).unwrap();
    ipv6::emit_fragment_header(&mut packet[40..], 60, 0, true, 1).unwrap();
    packet[48] = wire::PROTO_ICMPV6;
    packet[56] = 1;
    pending(push(&mut r, now, &packet));
    let late = now + Duration::from_secs(30);
    r.expire(late);
    assert!(r.pending_icmp());
    let mut icmp = IcmpOut::default();
    assert!(matches!(r.poll_icmp(late, &mut icmp, &mut [0; 1500]), Output::None));
    assert_eq!(icmp.suppressed, 1);
    assert_eq!(budget.used(), 0);
    r.assert_idle();
}
