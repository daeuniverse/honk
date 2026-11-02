use super::*;
use aya::maps::HashMap as AyaHashMap;
use honk_ebpf_common::conn::{FragmentKey, FragmentVerdict};

const PORT_FIRST: u16 = 40000;
/// The documented fragment record lifetime (doc/en/design/datapath.md),
/// deliberately not imported from production so a drifting value fails these tests.
const FRAGMENT_TTL_NS: u64 = 30_000_000_000;

/// One fragment of a UDP datagram. The first fragment carries the UDP header and MF;
/// a later fragment is the bare second 8-byte block.
fn fragment(src: IpAddr, dst: IpAddr, dst_port: u16, id: u32, first: bool) -> Vec<u8> {
    fragment_with_dscp(src, dst, dst_port, id, first, 0)
}

fn fragment_with_dscp(
    src: IpAddr,
    dst: IpAddr,
    dst_port: u16,
    id: u32,
    first: bool,
    dscp: u8,
) -> Vec<u8> {
    let mut frame = packet(src, dst, IPPROTO_UDP, PORT_FIRST, dst_port, dscp, 0);
    // The test device's all-zero address makes this PACKET_HOST, which the DNS fragment path requires.
    frame[..6].fill(0);
    match src {
        IpAddr::V4(_) => {
            if !first {
                frame.truncate(14 + 20 + 8);
                frame[16..18].copy_from_slice(&28u16.to_be_bytes());
            }
            frame[18..20].copy_from_slice(&(id as u16).to_be_bytes());
            let flags_offset: u16 = if first { 0x2000 } else { 1 };
            frame[20..22].copy_from_slice(&flags_offset.to_be_bytes());
            frame[24..26].fill(0);
            let checksum = internet_checksum(&[&frame[14..34]]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        }
        IpAddr::V6(_) => {
            let payload = if first {
                frame.split_off(54)
            } else {
                vec![0xa5; 8]
            };
            frame.truncate(54);
            frame[20] = 44;
            let offset_flags: u16 = if first { 1 } else { 1 << 3 };
            let mut header = vec![IPPROTO_UDP, 0];
            header.extend_from_slice(&offset_flags.to_be_bytes());
            header.extend_from_slice(&id.to_be_bytes());
            frame.extend_from_slice(&header);
            frame.extend_from_slice(&payload);
            let payload_len = (frame.len() - 54) as u16;
            frame[18..20].copy_from_slice(&payload_len.to_be_bytes());
        }
    }
    frame
}

fn families() -> [(IpAddr, IpAddr, IpAddr); 2] {
    [
        (
            "192.0.2.110".parse().unwrap(),
            "192.0.2.111".parse().unwrap(),
            "203.0.113.110".parse().unwrap(),
        ),
        (
            "2001:db8:1::110".parse().unwrap(),
            "2001:db8:1::111".parse().unwrap(),
            "2001:db8:2::110".parse().unwrap(),
        ),
    ]
}

fn fixture(outbound: &str, side: &str) -> (RealEbpfBackend, TproxyListeners) {
    let (mut backend, _, listeners) = publish(&[
        rule(
            "fragments",
            RoutingCondition {
                port: vec!["443".into()],
                ..Default::default()
            },
            outbound,
            USER_MARK,
            true,
        ),
        rule(
            "native",
            RoutingCondition {
                port: vec!["444".into()],
                ..Default::default()
            },
            "direct",
            0,
            true,
        ),
    ]);
    load_classifier(&mut backend, side);
    (backend, listeners)
}

fn verdict(backend: &RealEbpfBackend, side: &str, frame: &[u8]) -> u32 {
    run(backend, side, frame, SkbInput::default()).verdict
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn later_fragments_of_a_redirected_or_dropped_datagram_are_dropped() {
    isolated(|| {
        for (family, side, outbound, first_verdict, pass) in [
            (0, "lan_ingress_l2", "proxy", TC_ACT_REDIRECT, TC_ACT_OK),
            (1, "lan_ingress_l2", "block", TC_ACT_SHOT, TC_ACT_OK),
            (0, "wan_egress_l2", "block", TC_ACT_SHOT, TC_ACT_UNSPEC),
            (1, "wan_egress_l2", "proxy", TC_ACT_REDIRECT, TC_ACT_UNSPEC),
        ] {
            let (src, other_src, dst) = families()[family];
            let (mut backend, _listeners) = fixture(outbound, side);
            let id = 0x1234;
            let context = format!("{outbound} {side} family {family}");
            assert_eq!(
                verdict(&backend, side, &fragment(src, dst, 443, id, true)),
                first_verdict,
                "{context}: first fragment"
            );
            if family == 0 && side == "lan_ingress_l2" {
                // Pre-parse exits must not retire the preceding packet's record.
                let unrelated = fragment(src, dst, 444, id + 1, true);
                assert_eq!(
                    run(
                        &backend,
                        side,
                        &unrelated,
                        SkbInput {
                            mark: CLASSIFIED_MARK,
                            ..Default::default()
                        }
                    )
                    .verdict,
                    TC_ACT_OK
                );
                backend.set_datapath_ready(false).unwrap();
                assert_eq!(verdict(&backend, side, &unrelated), TC_ACT_UNSPEC);
                backend.set_datapath_ready(true).unwrap();
                for other in [
                    fragment(src, dst, 443, id + 7, false),
                    fragment(other_src, dst, 443, id, false),
                ] {
                    assert_eq!(verdict(&backend, side, &other), TC_ACT_OK);
                }

                backend
                    .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
                    .unwrap();
                let staged = run(
                    &backend,
                    side,
                    &fragment(src, dst, 445, 0x3000, true),
                    SkbInput::default(),
                );
                assert_eq!(staged.verdict, TC_ACT_OK);
                assert_ne!(staged.mark & NFQUEUE_TOKEN_MASK, 0);
                assert_eq!(
                    verdict(&backend, side, &fragment(src, dst, 445, 0x3000, false)),
                    TC_ACT_OK,
                    "NFQUEUE-staged fragments stay outside the drop cache"
                );
            }
            assert_eq!(
                verdict(&backend, side, &fragment(src, dst, 443, id, false)),
                TC_ACT_SHOT,
                "{context}: original datagram"
            );
            assert_eq!(
                verdict(&backend, side, &fragment(src, dst, 444, id, true)),
                TC_ACT_OK,
                "{context}: accepted first fragment"
            );
            assert_eq!(
                verdict(&backend, side, &fragment(src, dst, 444, id, false)),
                pass,
                "{context}: an accepted datagram reusing the ID must keep its tails"
            );
            assert_eq!(
                hash_count::<FragmentKey, FragmentVerdict>(&backend, "FRAG_VERDICT"),
                0,
                "{context}: stale record removed"
            );
        }

        // A dropped UDP/53 first fragment must not poison native DNS reassembly.
        let (src, _, dst) = families()[0];
        let (mut backend, _, _listeners) = publish(&dns_ordering_rules());
        load_classifier(&mut backend, "lan_ingress_l2");
        let dns = |first| fragment_with_dscp(src, dst, 53, 0x4000, first, 46);
        assert_eq!(verdict(&backend, "lan_ingress_l2", &dns(true)), TC_ACT_SHOT);
        assert_eq!(verdict(&backend, "lan_ingress_l2", &dns(false)), TC_ACT_OK);
    });
}

/// IPv6 Fragment -> Destination Options -> UDP: only the first fragment reaches
/// UDP, so its parsed protocol differs from the later fragments' (Destination
/// Options). Reassembly keys on source, destination and identification alone.
fn fragment_behind_destination_options(src: IpAddr, dst: IpAddr, id: u32, first: bool) -> Vec<u8> {
    const FRAGMENT_NEXT_HEADER: usize = 14 + 40;
    const FRAGMENT_END: usize = FRAGMENT_NEXT_HEADER + 8;
    const DESTINATION_OPTIONS: u8 = 60;
    let mut frame = fragment(src, dst, 443, id, first);
    frame[FRAGMENT_NEXT_HEADER] = DESTINATION_OPTIONS;
    if first {
        frame.splice(
            FRAGMENT_END..FRAGMENT_END,
            [IPPROTO_UDP, 0, 1, 4, 0, 0, 0, 0],
        );
        let payload_len = (frame.len() - 54) as u16;
        frame[18..20].copy_from_slice(&payload_len.to_be_bytes());
    }
    frame
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn later_fragments_behind_ipv6_extension_headers_inherit_the_first_fragments_fate() {
    isolated(|| {
        let (src, _, dst) = families()[1];
        let side = "lan_ingress_l2";
        let (backend, _listeners) = fixture("block", side);
        assert_eq!(
            verdict(
                &backend,
                side,
                &fragment_behind_destination_options(src, dst, 0x5000, true)
            ),
            TC_ACT_SHOT
        );
        assert_eq!(
            verdict(
                &backend,
                side,
                &fragment_behind_destination_options(src, dst, 0x5000, false)
            ),
            TC_ACT_SHOT,
            "the tail must be dropped with its first fragment"
        );
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn an_expired_fragment_record_does_not_affect_a_reused_datagram_id() {
    isolated(|| {
        // A fresh VM may have less uptime than the record TTL. Wait once for a
        // genuine old monotonic timestamp, rather than wrapping the backdated age.
        let wait_ns = (FRAGMENT_TTL_NS + 2_000_000_000).saturating_sub(monotonic_ns());
        if wait_ns != 0 {
            std::thread::sleep(std::time::Duration::from_nanos(wait_ns));
        }
        let (src, _, dst) = families()[0];
        let (mut backend, _listeners) = fixture("proxy", "lan_ingress_l2");
        let later = fragment(src, dst, 443, 0x5000, false);
        assert_eq!(
            verdict(
                &backend,
                "lan_ingress_l2",
                &fragment(src, dst, 443, 0x5000, true)
            ),
            TC_ACT_REDIRECT
        );
        assert_eq!(verdict(&backend, "lan_ingress_l2", &later), TC_ACT_SHOT);

        let map = backend.bpf_mut().unwrap().map_mut("FRAG_VERDICT").unwrap();
        let mut map = AyaHashMap::<_, FragmentKey, FragmentVerdict>::try_from(map).unwrap();
        let keys: Vec<_> = map.keys().map(Result::unwrap).collect();
        assert_eq!(keys.len(), 1);
        let mut aged = map.get(&keys[0], 0).unwrap();
        aged.ktime_ns = monotonic_ns() - FRAGMENT_TTL_NS - 1_000_000_000;
        map.insert(&keys[0], &aged, 0).unwrap();
        assert_eq!(verdict(&backend, "lan_ingress_l2", &later), TC_ACT_OK);
    });
}

fn monotonic_ns() -> u64 {
    let mut time: libc::timespec = unsafe { mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) },
        0
    );
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}
