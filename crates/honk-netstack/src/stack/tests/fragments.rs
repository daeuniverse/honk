use super::*;
use crate::wire::{ipv6, udp};

fn terminator(now: Instant) -> Stack {
    let mut cfg = Config::new([7; 32]);
    cfg.mode = Mode::Transparent {
        exclude: crate::ExcludeSet::default(),
    };
    Stack::new(cfg, now)
}

fn fragment(next: u8, data: &[u8], offset: usize, more: bool, id: u32) -> Vec<u8> {
    let mut packet = vec![0; 48 + data.len()];
    ipv6::emit(
        &mut packet,
        "fd00::2".parse().unwrap(),
        "fd00::7".parse().unwrap(),
        44,
        8 + data.len(),
    )
    .unwrap();
    ipv6::emit_fragment_header(&mut packet[40..], next, offset, more, id).unwrap();
    packet[48..].copy_from_slice(data);
    packet
}

#[test]
fn nested_ipv6_fragment_headers_are_dropped_even_behind_extensions() {
    let now = Instant::now();
    let mut stack = terminator(now);
    let mut whole = [0; 128];
    let n = udp::emit_packet(
        &mut whole,
        "[fd00::2]:5000".parse().unwrap(),
        "[fd00::7]:53".parse().unwrap(),
        b"nested fragment headers",
    )
    .unwrap();
    let atomic = fragment(wire::PROTO_UDP, &whole[40..n], 0, false, 1);
    assert!(matches!(
        stack.receive(now, &atomic),
        Rx::TransparentOwned { .. }
    ));
    for extensions in [false, true] {
        let mut data = Vec::new();
        if extensions {
            data.extend_from_slice(&[44, 0, 0, 0, 0, 0, 0, 0]);
        }
        data.extend_from_slice(&atomic[40..]);
        let next = if extensions { 60 } else { 44 };
        for atomic_outer in [true, false] {
            let mut stack = terminator(now);
            if atomic_outer {
                let packet = fragment(next, &data, 0, false, 2);
                assert_eq!(stack.receive(now, &packet), Rx::Dropped(DropReason::Fragment));
            } else {
                let first = fragment(next, &data[..16], 0, true, 2);
                let last = fragment(next, &data[16..], 16, false, 2);
                assert_eq!(stack.receive(now, &first), Rx::Consumed);
                assert_eq!(stack.receive(now, &last), Rx::Dropped(DropReason::Fragment));
            }
            assert_eq!(stack.reasm.len(), 0);
            assert_eq!(stack.reasm.bytes(), 0);
            assert!(stack.poll_timeout().is_none());
        }
    }
}
