use super::*;
use crate::{Config, ExcludeSet, Mode, Stack};

fn receiver(budget: &Arc<MemoryBudget>, now: Instant) -> Stack {
    let mut cfg = Config::new([7; 32]);
    cfg.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    cfg.shared_budget = Some(Arc::clone(budget));
    Stack::new(cfg, now)
}

fn owned(stack: &mut Stack, now: Instant, original: &[u8], id: u32) -> OwnedPacket {
    let ip = wire::parse_ip(original).unwrap();
    let expected = &original[ip.payload.start + 8..ip.payload.end];
    let mut result = None;
    for fragment in split(original, id, 1000) {
        match stack.receive(now, &fragment) {
            Rx::Consumed => {}
            Rx::TransparentOwned {
                src,
                dst,
                dscp,
                packet,
                payload,
            } => {
                assert_eq!((src.ip(), dst.ip()), (ip.src, ip.dst));
                assert_eq!(dscp, ip.dscp);
                assert_eq!(&packet[payload], expected);
                assert!(
                    result.replace(packet).is_none(),
                    "one completed datagram per original"
                );
            }
            other => panic!("unexpected reassembly outcome: {other:?}"),
        }
    }
    let packet = result.expect("all fragments must complete");
    assert_eq!(
        packet.ipv6_fragment(),
        ip.src.is_ipv6().then_some(Ipv6Fragment {
            id,
            max_size: 48 + ip.payload.len().min(1000),
        })
    );
    packet
}

#[test]
fn completed_packets_outlive_their_stacks_without_releasing_capacity() {
    for (src, dst) in families() {
        let now = Instant::now();
        let budget = MemoryBudget::new(20_000);
        let mut a = receiver(&budget, now);
        let mut b = receiver(&budget, now);
        let first = datagram(src, dst, 3000, 1);
        let second = datagram(src, dst, 1800, 2);
        let a_packet = owned(&mut a, now, &first, 1);
        assert_eq!(budget.used(), first.len());
        let b_packet = owned(&mut b, now, &second, 2);
        assert_eq!(budget.used(), first.len() + second.len());
        drop(a);
        drop(b);
        assert_eq!(budget.used(), a_packet.len() + b_packet.len());
        drop(a_packet);
        assert_eq!(budget.used(), b_packet.len());
        let weak = Arc::downgrade(&budget);
        drop(budget);
        assert!(weak.upgrade().is_some(), "the packet still owns its budget");
        drop(b_packet);
        assert!(
            weak.upgrade().is_none(),
            "the last packet releases the budget owner"
        );
    }
}

#[test]
fn independent_stacks_refuse_completion_without_refunding_held_packets() {
    for (src, dst) in families() {
        let now = Instant::now();
        let budget = MemoryBudget::new(8000);
        let mut a = receiver(&budget, now);
        let mut b = receiver(&budget, now);
        let first = datagram(src, dst, 3000, 1);
        let second = datagram(src, dst, 1800, 2);
        let a_packet = owned(&mut a, now, &first, 1);
        let b_packet = owned(&mut b, now, &second, 2);
        let held = first.len() + second.len();
        assert_eq!(budget.used(), held);

        let fragments = split(&second, 3, 1000);
        for fragment in &fragments[..fragments.len() - 1] {
            assert_eq!(b.receive(now, fragment), Rx::Consumed);
        }
        assert!(
            budget.used() > held,
            "the second stack retains partial reassembly"
        );
        assert_eq!(
            b.receive(now, fragments.last().unwrap()),
            Rx::Dropped(DropReason::Capacity)
        );
        assert_eq!(b.stats().drops[DropReason::Capacity as usize], 1);
        assert_eq!(b.stats().flows, 0);
        assert_eq!(budget.used(), held);
        assert_eq!(
            &a_packet[a_packet.len() - 3000..],
            &first[first.len() - 3000..]
        );
        assert_eq!(
            &b_packet[b_packet.len() - 1800..],
            &second[second.len() - 1800..]
        );

        drop(b_packet);
        assert_eq!(budget.used(), first.len());
        let retry = owned(&mut b, now, &second, 4);
        assert_eq!(budget.used(), held);
        drop(a);
        drop(b);
        assert_eq!(budget.used(), held);
        assert_eq!(
            &a_packet[a_packet.len() - 3000..],
            &first[first.len() - 3000..]
        );
        drop(retry);
        assert_eq!(budget.used(), first.len());
        drop(a_packet);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn completion_reserves_the_copy_before_refunding_fragment_storage() {
    for (src, dst) in families() {
        let now = Instant::now();
        let budget = MemoryBudget::new(20_000);
        let mut reassembly = Reassembler::default().with_budget(Some(Arc::clone(&budget)));
        let original = datagram(src, dst, 3000, 4);
        let fragments = split(&original, 9, 1000);
        for fragment in fragments[1..].iter().rev() {
            pending(push(&mut reassembly, now, fragment));
        }
        let other = budget
            .reserve(budget.limit() - budget.used() - 128)
            .unwrap();
        assert!(matches!(
            push(&mut reassembly, now, &fragments[0]),
            Push::Dropped(DropReason::Capacity)
        ));
        assert_eq!(reassembly.stats.completed, 0);
        reassembly.assert_idle();
        assert_eq!(budget.used(), other.bytes());
        drop(other);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn atomic_ipv6_datagrams_cannot_bypass_the_shared_capacity_limit() {
    let now = Instant::now();
    let (src, dst) = families()[1];
    let original = datagram(src, dst, 1200, 5);
    let atomic = split(&original, 1, original.len()).pop().unwrap();
    let budget = MemoryBudget::new(2 * original.len());
    let mut stack = receiver(&budget, now);
    let first = stack.receive(now, &atomic);
    let second = stack.receive(now, &atomic);
    assert!(matches!(first, Rx::TransparentOwned { .. }));
    assert!(matches!(second, Rx::TransparentOwned { .. }));
    assert_eq!(budget.used(), budget.limit());
    assert_eq!(
        stack.receive(now, &atomic),
        Rx::Dropped(DropReason::Capacity)
    );
    assert_eq!(stack.stats().flows, 0);
    assert_eq!(stack.stats().drops[DropReason::Capacity as usize], 1);
    drop(first);
    assert_eq!(budget.used(), original.len());
    let next = datagram(src, dst, 1200, 6);
    let next_atomic = split(&next, 2, next.len()).pop().unwrap();
    let next_packet = stack.receive(now, &next_atomic);
    assert!(matches!(next_packet, Rx::TransparentOwned { .. }));
    assert_eq!(budget.used(), budget.limit());
    drop(second);
    drop(next_packet);
    assert_eq!(budget.used(), 0);
}

#[test]
fn checksum_rejection_releases_the_completed_packet_charge() {
    for (src, dst) in families() {
        let now = Instant::now();
        let budget = MemoryBudget::new(20_000);
        let mut stack = receiver(&budget, now);
        let mut original = datagram(src, dst, 3000, 7);
        *original.last_mut().unwrap() ^= 1;
        let fragments = split(&original, 3, 1000);
        for fragment in &fragments[..fragments.len() - 1] {
            assert_eq!(stack.receive(now, fragment), Rx::Consumed);
        }
        assert_eq!(
            stack.receive(now, fragments.last().unwrap()),
            Rx::Dropped(DropReason::Checksum)
        );
        assert_eq!(budget.used(), 0);
        assert_eq!(stack.stats().flows, 0);
    }
}
