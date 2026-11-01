use super::*;
use std::io::Write;
use udp_group::UdpGroup;

const FLOWS: u16 = 16;
const DATAGRAMS: usize = 3;

/// Every datagram of a flow must reach one listener, the one `sk_lookup`
/// names for that tuple: TC assignment and the lookup program share one index.
#[track_caller]
fn assert_flow_on_lookup_listener(
    fixture: &NetworkFixture,
    group: &UdpGroup,
    source: SocketAddr,
    destination: SocketAddr,
    used: &mut [bool; udp_group::LISTENERS],
) {
    let mut first = None;
    for _ in 0..DATAGRAMS {
        let (index, observed) = group.receiver(destination.is_ipv6());
        assert_eq!(observed, source);
        assert_eq!(
            *first.get_or_insert(index),
            index,
            "{source} changed listener"
        );
    }
    let index = first.unwrap();
    assert_eq!(
        fixture.lookup_cookie(source, destination),
        group.cookie(destination.is_ipv6(), index),
        "{source} -> {destination}: TC assignment and sk_lookup pick different listeners"
    );
    used[index] = true;
}

#[test]
#[ignore = "requires root, Linux with SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, veth/netkit, and isolated netns support"]
fn udp_flows_from_l2_clients_keep_their_listener() {
    for use_redirect_peer in [0, 1] {
        isolated(move || {
            let mut fixture = NetworkFixture::new(use_redirect_peer);
            let group = fixture.udp_group();
            for destination in [
                "198.51.100.53:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8:81::53]:53".parse().unwrap(),
            ] {
                let mut used = [false; udp_group::LISTENERS];
                for _ in 0..FLOWS {
                    let client = fixture.udp_client(destination, DSCP_RAW_MUST);
                    for _ in 0..DATAGRAMS {
                        client.send_to(b"q", destination).unwrap();
                    }
                    assert_flow_on_lookup_listener(
                        &fixture,
                        &group,
                        client.local_addr().unwrap(),
                        destination,
                        &mut used,
                    );
                }
                assert!(
                    used.iter().filter(|used| **used).count() >= 2,
                    "{destination}: flows did not spread over the listeners"
                );
            }
        });
    }
}

/// Writes each frame with the last `link_header` bytes of its Ethernet header kept
/// (0 bare IP, 14 full Ethernet) into an `_l3`-bound device.
fn assert_l3_link_flows_keep_their_listener(
    fixture: &mut NetworkFixture,
    device: &mut std::fs::File,
    link_header: usize,
) {
    let group = fixture.udp_group();
    for (source, destination) in [
        (
            "10.82.0.2".parse::<IpAddr>().unwrap(),
            "198.51.100.53".parse::<IpAddr>().unwrap(),
        ),
        (
            "fd83::2".parse().unwrap(),
            "2001:db8:81::53".parse().unwrap(),
        ),
    ] {
        let mut used = [false; udp_group::LISTENERS];
        for flow in 0..FLOWS {
            let port = 45000 + flow * 7;
            let bytes = packet(source, destination, IPPROTO_UDP, port, 53, DSCP_RAW_MUST, 0);
            for _ in 0..DATAGRAMS {
                device.write_all(&bytes[14 - link_header..]).unwrap();
            }
            assert_flow_on_lookup_listener(
                fixture,
                &group,
                SocketAddr::new(source, port),
                SocketAddr::new(destination, 53),
                &mut used,
            );
        }
        assert!(
            used.iter().filter(|used| **used).count() >= 2,
            "{destination}: flows did not spread over the listeners"
        );
    }
}

#[test]
#[ignore = "requires root, Linux with TUN, SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, redirect_peer, veth/netkit, and isolated netns support"]
fn udp_flows_from_l3_tun_keep_their_listener() {
    isolated(|| {
        let mut fixture = NetworkFixture::new(1);
        let mut tun = fixture.l3_tun();
        assert_l3_link_flows_keep_their_listener(&mut fixture, &mut tun, 0);
    });
}

#[test]
#[ignore = "requires root, Linux with TUN, SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, redirect_peer, veth/netkit, and isolated netns support"]
fn udp_flows_from_rawip_typed_ethernet_link_keep_their_listener() {
    isolated(|| {
        let mut fixture = NetworkFixture::new(1);
        let mut tap = fixture.rawip_tap();
        assert_l3_link_flows_keep_their_listener(&mut fixture, &mut tap, 14);
    });
}
