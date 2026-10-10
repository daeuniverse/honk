use super::*;
use crate::control::tests::support::{addr, bytes_of, dns_query_payload};
use crate::dns::query::is_exact_dns_query;

#[test]
fn udp_original_dst_unspecified_origdst_is_authoritative_and_fails_closed() {
    let meta = UdpRecvMeta {
        packet_priority: None,
        original_dst_cmsg: Some(addr("0.0.0.0:53")),
        packet_dst_ip: Some("198.51.100.53".parse().unwrap()),
        packet_ifindex: None,
        local_addr: addr("192.0.2.20:5353"),
        packet_mark: None,
    };

    assert!(udp_original_dst(&meta, &dns_query_payload()).is_none());
}
#[test]
fn udp_original_dst_cmsg_takes_precedence_over_other_metadata() {
    let meta = UdpRecvMeta {
        packet_priority: None,
        original_dst_cmsg: Some(addr("203.0.113.10:4444")),
        packet_dst_ip: Some("198.51.100.10".parse().unwrap()),
        packet_ifindex: None,
        packet_mark: None,
        local_addr: addr("192.0.2.10:5353"),
    };

    let destination = udp_original_dst(&meta, b"not a DNS query").unwrap();
    assert_eq!(destination.address, addr("203.0.113.10:4444"));
    assert!(destination.validated_dns.is_none());
}

#[test]
fn udp_original_dst_uses_ipv4_pktinfo_for_exact_dns_query() {
    let expected_ip = std::net::Ipv4Addr::new(198, 51, 100, 53);
    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(expected_ip).to_be(),
        },
    };
    let packet_dst_ip =
        packet_dst_ip_from_cmsg(libc::IPPROTO_IP, libc::IP_PKTINFO, bytes_of(&pktinfo));
    assert_eq!(packet_dst_ip, Some(std::net::IpAddr::V4(expected_ip)));

    let meta = UdpRecvMeta {
        packet_priority: None,
        original_dst_cmsg: None,
        packet_dst_ip,
        packet_ifindex: None,
        packet_mark: None,
        local_addr: addr("0.0.0.0:15000"),
    };
    let destination = udp_original_dst(&meta, &dns_query_payload()).unwrap();
    assert_eq!(destination.address, addr("198.51.100.53:53"));
    assert!(destination.validated_dns.is_some());
}

#[test]
fn udp_original_dst_uses_ipv6_pktinfo_for_exact_dns_query() {
    let expected_ip: std::net::Ipv6Addr = "2001:db8::53".parse().unwrap();
    let pktinfo = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: expected_ip.octets(),
        },
        ipi6_ifindex: 0,
    };
    let packet_dst_ip =
        packet_dst_ip_from_cmsg(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, bytes_of(&pktinfo));
    assert_eq!(packet_dst_ip, Some(std::net::IpAddr::V6(expected_ip)));

    let meta = UdpRecvMeta {
        packet_priority: None,
        original_dst_cmsg: None,
        packet_dst_ip,
        packet_ifindex: None,
        packet_mark: None,
        local_addr: addr("[::]:15000"),
    };
    let destination = udp_original_dst(&meta, &dns_query_payload()).unwrap();
    assert_eq!(destination.address, addr("[2001:db8::53]:53"));
    assert!(destination.validated_dns.is_some());
}

#[test]
fn udp_original_dst_uses_non_wildcard_local_fallback() {
    let local_addr = addr("192.0.2.20:5353");
    let meta = UdpRecvMeta {
        packet_priority: None,
        original_dst_cmsg: None,
        packet_dst_ip: None,
        packet_ifindex: None,
        packet_mark: None,
        local_addr,
    };

    let destination = udp_original_dst(&meta, b"opaque UDP").unwrap();
    assert_eq!(destination.address, local_addr);
    assert!(destination.validated_dns.is_none());
    let dns_destination = udp_original_dst(&meta, &dns_query_payload()).unwrap();
    assert_eq!(dns_destination.address, local_addr);
    assert!(dns_destination.validated_dns.is_some());
}

#[test]
fn udp_original_dst_fails_closed_for_wildcard_local_without_metadata() {
    for local_addr in [addr("0.0.0.0:15000"), addr("[::]:15000")] {
        let meta = UdpRecvMeta {
            packet_priority: None,
            original_dst_cmsg: None,
            packet_dst_ip: None,
            packet_ifindex: None,
            packet_mark: None,
            local_addr,
        };
        assert!(udp_original_dst(&meta, b"opaque UDP").is_none());
    }
}

#[test]
fn udp_original_dst_does_not_rewrite_non_exact_dns_payloads() {
    let packet_meta = UdpRecvMeta {
        packet_priority: None,
        original_dst_cmsg: None,
        packet_dst_ip: Some("198.51.100.53".parse().unwrap()),
        packet_ifindex: None,
        packet_mark: None,
        local_addr: addr("0.0.0.0:15000"),
    };
    let local_fallback = addr("192.0.2.20:5353");
    let fallback_meta = UdpRecvMeta {
        packet_priority: None,
        original_dst_cmsg: None,
        packet_dst_ip: None,
        packet_ifindex: None,
        packet_mark: None,
        local_addr: local_fallback,
    };
    let mut dns_response = dns_query_payload();
    dns_response[2] |= 0x80;

    for payload in [
        dns_response.as_slice(),
        b"short".as_slice(),
        &[0u8; 20][..],
        b"random non-53 UDP payload".as_slice(),
    ] {
        assert!(!is_exact_dns_query(payload));
        assert!(udp_original_dst(&packet_meta, payload).is_none());
        let destination = udp_original_dst(&fallback_meta, payload).unwrap();
        assert_eq!(destination.address, local_fallback);
        assert!(destination.validated_dns.is_none());
    }
}
