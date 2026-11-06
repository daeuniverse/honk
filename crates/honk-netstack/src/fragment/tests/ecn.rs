use super::*;
use crate::transit::Transit;
use crate::wire::PacketView;

const DSCP: [u8; 3] = [45, 3, 61];
const FLOW_LABEL: [u32; 3] = [0xABCDE, 0x12345, 0xFEDCB];
const PADDING: usize = 3;
const ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

fn mark(packet: &mut [u8], traffic_class: u8, label: u32, hop_limit: u8) {
    if packet[0] >> 4 == 6 {
        let first = 0x6000_0000 | (u32::from(traffic_class) << 20) | label;
        packet[..4].copy_from_slice(&first.to_be_bytes());
        packet[7] = hop_limit;
    } else {
        packet[1] = traffic_class;
        packet[8] = hop_limit;
        packet[10..12].fill(0);
        let len = usize::from(packet[0] & 15) * 4;
        let sum = wire::checksum::checksum(&packet[..len]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
    }
}

fn traffic_class(packet: &[u8]) -> u8 {
    if packet[0] >> 4 == 6 {
        (packet[0] & 15) << 4 | packet[1] >> 4
    } else {
        packet[1]
    }
}

fn fragments(whole: &[u8], id: u32, ecn: [u8; 3]) -> Vec<Vec<u8>> {
    let mut packets = split(whole, id, 8);
    assert_eq!(packets.len(), 3);
    for (index, packet) in packets.iter_mut().enumerate() {
        if packet[0] >> 4 == 6 {
            let len = u16::from_be_bytes([packet[4], packet[5]]) + 8;
            packet.splice(40..40, [44, 0, 1, 4, 0, 0, 0, 0]);
            packet[6] = 60;
            packet[4..6].copy_from_slice(&len.to_be_bytes());
        }
        mark(
            packet,
            DSCP[index] << 2 | ecn[index],
            FLOW_LABEL[index],
            31 + index as u8,
        );
        packet.extend_from_slice(&[0xE5; PADDING]);
    }
    packets
}

#[test]
fn ecn_reassembly_merges_all_codepoint_combinations_in_every_fragment_order() {
    let now = Instant::now();
    let limits = FragmentLimits::default();
    let deadline = now + limits.timeout;
    for (src, dst) in families() {
        let whole = datagram(src, dst, 13, 19);
        let original = wire::parse_ip(&whole).unwrap();
        for first in 0..4 {
            for middle in 0..4 {
                for last in 0..4 {
                    let ecn = [first, middle, last];
                    let packets = fragments(&whole, 0x1234_5678, ecn);
                    for order in ORDERS {
                        let budget = MemoryBudget::new(16 << 20);
                        let mut transit = Transit::new(Arc::clone(&budget), limits).unwrap();
                        let baseline = budget.used();
                        let mut seen = 0;
                        for (arrival, index) in order.into_iter().enumerate() {
                            seen |= 1 << ecn[index];
                            let invalid = seen & 1 != 0 && seen != 1;
                            let result = transit.reassemble(
                                now + Duration::from_millis(arrival as u64),
                                &packets[index],
                            );
                            if invalid {
                                assert_eq!(result, Err(DropReason::Fragment), "{ecn:?} {order:?}");
                                assert_eq!(transit.fragment_obligations().count(), 0);
                                assert_eq!(budget.used(), baseline + ENTRY_OVERHEAD);
                            } else if arrival != 2 {
                                assert!(result.unwrap().is_none());
                                let domains = transit.fragment_obligations();
                                assert_eq!(
                                    domains.clone().collect::<Vec<_>>(),
                                    [(src, dst, wire::PROTO_UDP)]
                                );
                                assert_eq!(
                                    domains.collect::<Vec<_>>(),
                                    [(src, dst, wire::PROTO_UDP)]
                                );
                            } else {
                                let packet = result.unwrap().expect("all fragment bytes arrived");
                                let ip = PacketView::from_slice(&packet)
                                    .validate_transport()
                                    .unwrap();
                                let merged = if ecn.contains(&3) { 3 } else { first };
                                assert_eq!(
                                    traffic_class(&packet),
                                    DSCP[0] << 2 | merged,
                                    "{ecn:?} {order:?}"
                                );
                                assert_eq!((ip.dscp, ip.hop_limit), (DSCP[0], 31));
                                assert_eq!(&packet[ip.payload], &whole[original.payload.clone()]);
                                if src.is_ipv6() {
                                    let prefix =
                                        u32::from_be_bytes(packet[..4].try_into().unwrap());
                                    assert_eq!(prefix & 0xFFFFF, FLOW_LABEL[0]);
                                    assert_eq!((packet[6], packet[40]), (60, wire::PROTO_UDP));
                                    assert_eq!(
                                        packet.ipv6_fragment(),
                                        Some(Ipv6Fragment {
                                            id: 0x1234_5678,
                                            max_size: packets[0].len() - PADDING,
                                        })
                                    );
                                } else {
                                    assert_eq!(&packet[4..8], &[0x56, 0x78, 0, 0]);
                                }
                                assert!(transit.is_quiescent());
                                assert_eq!(budget.used(), baseline + packet.len());
                                drop(packet);
                                assert_eq!(budget.used(), baseline);
                            }
                            if arrival != 2 || invalid {
                                assert_eq!(transit.poll_timeout(), Some(deadline));
                            }
                        }
                        if seen & 1 != 0 && seen != 1 {
                            for packet in &packets {
                                assert_eq!(
                                    transit.reassemble(deadline - Duration::from_millis(1), packet),
                                    Err(DropReason::Fragment)
                                );
                            }
                            assert_eq!(transit.poll_timeout(), Some(deadline));
                            assert!(!transit.is_quiescent());
                            transit.expire(deadline);
                            assert!(transit.poll_expired_quote().is_none());
                        }
                        assert!(transit.is_quiescent());
                        assert_eq!(transit.poll_timeout(), None);
                        assert_eq!(budget.used(), baseline);
                        drop(transit);
                        assert_eq!(budget.used(), 0);
                    }
                }
            }
        }
    }
}

#[test]
fn ecn_timeout_quotes_and_overlap_keep_original_ownership_and_deadline() {
    let now = Instant::now();
    let limits = FragmentLimits::default();
    let deadline = now + limits.timeout;
    for (src, dst) in families() {
        let whole = datagram(src, dst, 13, 20);
        let packets = fragments(&whole, 7, [2, 2, 3]);
        let budget = MemoryBudget::new(16 << 20);
        let mut transit = Transit::new(Arc::clone(&budget), limits).unwrap();
        let baseline = budget.used();
        assert!(transit.reassemble(now, &packets[2]).unwrap().is_none());
        assert!(
            transit
                .reassemble(now + Duration::from_secs(1), &packets[0])
                .unwrap()
                .is_none()
        );
        assert_eq!(transit.poll_timeout(), Some(deadline));
        transit.expire(deadline);
        assert_eq!(
            transit.fragment_obligations().collect::<Vec<_>>(),
            [(src, dst, wire::PROTO_UDP)]
        );
        let quote = transit
            .poll_expired_quote()
            .expect("fragment zero permits timeout quote");
        assert_eq!(quote.as_ref(), &packets[0][..packets[0].len() - PADDING]);
        assert_eq!(traffic_class(&quote), DSCP[0] << 2 | 2);
        assert!(transit.is_quiescent());
        assert_eq!(transit.fragment_obligations().count(), 0);
        assert_eq!(budget.used(), baseline + quote.len());
        drop(quote);
        assert_eq!(budget.used(), baseline);

        let start = deadline + Duration::from_secs(1);
        assert!(transit.reassemble(start, &packets[0]).unwrap().is_none());
        let mut duplicate = packets[0].clone();
        mark(&mut duplicate, DSCP[0] << 2 | 3, FLOW_LABEL[0], 31);
        assert_eq!(
            transit.reassemble(start + Duration::from_secs(1), &duplicate),
            Err(DropReason::Fragment)
        );
        assert_eq!(transit.fragment_obligations().count(), 0);
        assert_eq!(transit.poll_timeout(), Some(start + limits.timeout));
        assert_eq!(budget.used(), baseline + ENTRY_OVERHEAD);
        for packet in &packets[1..] {
            assert_eq!(
                transit.reassemble(start + Duration::from_secs(2), packet),
                Err(DropReason::Fragment)
            );
        }
        transit.expire(start + limits.timeout);
        assert!(transit.poll_expired_quote().is_none());
        assert!(transit.is_quiescent());
        assert_eq!(budget.used(), baseline);

        let retry = start + limits.timeout;
        assert!(transit.reassemble(retry, &packets[2]).unwrap().is_none());
        assert!(transit.reassemble(retry, &packets[0]).unwrap().is_none());
        let packet = transit.reassemble(retry, &packets[1]).unwrap().unwrap();
        PacketView::from_slice(&packet)
            .validate_transport()
            .unwrap();
        assert_eq!(traffic_class(&packet), DSCP[0] << 2 | 3);
        assert!(transit.is_quiescent());
        drop(packet);
        assert_eq!(budget.used(), baseline);
    }
}

#[test]
fn ipv6_atomic_ecn_does_not_merge_with_same_id_pending_fragments() {
    let now = Instant::now();
    let (src, dst) = families()[1];
    let whole = datagram(src, dst, 13, 21);
    for last_ecn in [2, 3] {
        let packets = fragments(&whole, 9, [2, 2, last_ecn]);
        let budget = MemoryBudget::new(16 << 20);
        let mut transit = Transit::new(budget, FragmentLimits::default()).unwrap();
        assert!(transit.reassemble(now, &packets[2]).unwrap().is_none());
        let deadline = transit.poll_timeout();
        for ecn in [0, 3] {
            let mut atomic = split(&whole, 9, whole.len()).pop().unwrap();
            mark(&mut atomic, DSCP[0] << 2 | ecn, FLOW_LABEL[0], 31);
            let complete = transit.reassemble(now, &atomic).unwrap().unwrap();
            PacketView::from_slice(&complete)
                .validate_transport()
                .unwrap();
            assert_eq!(traffic_class(&complete), DSCP[0] << 2 | ecn);
            assert_eq!(transit.poll_timeout(), deadline);
            assert_eq!(
                transit.fragment_obligations().collect::<Vec<_>>(),
                [(src, dst, wire::PROTO_UDP)]
            );
        }
        assert!(transit.reassemble(now, &packets[0]).unwrap().is_none());
        let complete = transit.reassemble(now, &packets[1]).unwrap().unwrap();
        PacketView::from_slice(&complete)
            .validate_transport()
            .unwrap();
        assert_eq!(traffic_class(&complete), DSCP[0] << 2 | last_ecn);
        assert!(transit.is_quiescent());
    }
}
