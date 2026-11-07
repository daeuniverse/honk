use super::*;
use honk_ebpf_common::conn::TcpState;
use nix::sched::{CpuSet, sched_setaffinity};
use nix::unistd::Pid;

fn hints(ring: &mut RingBuf<aya::maps::MapData>) -> Vec<DaeEvent> {
    let mut events = Vec::new();
    while let Some(item) = ring.next() {
        let event: DaeEvent = unsafe { ptr::read_unaligned(item.as_ptr().cast()) };
        assert_eq!(event.type_, DaeEventType::FlowExpired as u32);
        events.push(event);
    }
    events
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn repeated_expiry_hints_are_bounded_without_renewing_or_releasing_refused_flows() {
    isolated(|| {
        let mut affinity = CpuSet::new();
        affinity
            .set(unsafe { libc::sched_getcpu() } as usize)
            .unwrap();
        sched_setaffinity(Pid::from_raw(0), &affinity).unwrap();
        // Fresh VM clocks need genuine past timestamps, never wrapping ages.
        let wait = 121_000_000_000u64.saturating_sub(now_ns());
        if wait != 0 {
            std::thread::sleep(Duration::from_nanos(wait));
        }
        let (src, dst) = PEERS[0];
        let (mut backend, _, _listeners) = proxy_fixture();
        let mut ring = RingBuf::try_from(
            backend
                .bpf_mut()
                .unwrap()
                .take_map("EVENT_RINGBUF")
                .unwrap(),
        )
        .unwrap();
        for side in ["lan_ingress_l2", "wan_egress_l2"] {
            for (index, (proto, state, age)) in [
                (IPPROTO_UDP, UdpDecisionState::None as u8, 121_000_000_000),
                (IPPROTO_UDP, UdpDecisionState::Aborted as u8, 0),
                (IPPROTO_TCP, TcpState::TcpStateClosing as u8, 11_000_000_000),
            ]
            .into_iter()
            .enumerate()
            {
                let key = tuple(src, dst, 45500 + index as u16, 443, proto);
                seed(&backend, side, &key, src, dst);
                let mut expired = backend.conn_state_lookup(&key).unwrap().unwrap();
                expired.state = state;
                expired.last_seen_ns = now_ns() - age;
                backend
                    .flow_insert("CONN_STATE_MAP", &key, &expired)
                    .unwrap();
                let before = owned_values(&backend, &key);
                let bytes = packet(src, dst, proto, key.src_port, key.dst_port, 0, 0x10);
                for _ in 0..2 {
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        TC_ACT_SHOT
                    );
                }
                assert_eq!(owned_values(&backend, &key), before);
                let events = hints(&mut ring);
                assert_eq!(events.len(), 1, "{side}: repeated {proto}/{state} hints");
                assert_eq!(events[0].incarnation, expired.incarnation);
                assert_eq!(events[0].sport, key.src_port);

                // A new incarnation must never inherit an old owner's suppression.
                expired.incarnation += 10_000;
                backend
                    .flow_insert("CONN_STATE_MAP", &key, &expired)
                    .unwrap();
                assert_eq!(
                    run(&backend, side, &bytes, SkbInput::default()).verdict,
                    TC_ACT_SHOT
                );
                let events = hints(&mut ring);
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].incarnation, expired.incarnation);

                // The hint cache is advisory: refusal persists across its interval.
                std::thread::sleep(Duration::from_millis(1010));
                assert_eq!(
                    run(&backend, side, &bytes, SkbInput::default()).verdict,
                    TC_ACT_SHOT
                );
                assert_eq!(hints(&mut ring).len(), 1);
                backend
                    .hash_remove::<_, FlowMapValue<ConnState>>("CONN_STATE_MAP", &key)
                    .unwrap();
                backend
                    .hash_remove::<_, FlowMapValue<RoutingHandoffEntry>>(
                        "ROUTING_HANDOFF_MAP",
                        &key,
                    )
                    .unwrap();
                backend
                    .hash_remove::<_, FlowMapValue<RedirectEntry>>(
                        "REDIRECT_TRACK",
                        &RedirectTuple::from_tuples(&key),
                    )
                    .unwrap();
            }
        }
    });
}
