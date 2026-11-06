use super::*;
use crate::control::tests::support::{addr, bytes_of, dns_query_payload};
use crate::dns::query::is_exact_dns_query;

#[cfg(feature = "dns-syslog")]
#[tokio::test]
async fn transparent_udp_admission_captures_audit_before_dispatch() {
    let mut config = honk_config::Config::default();
    config.global.syslog_dns_enabled = true;
    config.global.syslog_addr = "192.0.2.10:5514".into();
    let plane = crate::control::tests::support::control_plane(config.clone());
    let query = dns_query_payload();
    let client = addr("192.0.2.8:53000");
    let work = begin_udp_dns_query(
        &plane.dns_controller,
        &plane.stats,
        DatagramPayload::Borrowed(&query),
        validate_exact_dns_query(&query).unwrap(),
        client,
    );
    let UdpSlowPathWork::Dns {
        audit: Some(pending),
        ..
    } = work
    else {
        panic!("transparent DNS must capture audit before dispatch");
    };
    assert_eq!(
        crate::audit::tests::test_pending_event(pending)["event"],
        "dns.query"
    );
}

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

#[cfg(feature = "native-api")]
#[tokio::test]
async fn transparent_dns_refusal_records_flow_evidence_without_dns_log() {
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    let mut config = honk_config::Config::default();
    config.global.nfqueue_enable = false;
    config.global.store_subscribe = false;
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.record_dns_log = false;
    config.experimental.native_api.listen = api_addr.to_string();
    config.experimental.native_api.secret = "refusal-flow-test".into();
    config.ensure_builtin_nodes();
    let mut plane = crate::control::tests::support::control_plane(config);
    let state = Arc::new(
        crate::native_api::NativeState::new(
            &mut plane,
            api_addr,
            std::time::SystemTime::now(),
            std::time::Instant::now(),
        )
        .await
        .unwrap(),
    );
    let native = Arc::clone(&state.observation);
    let api_server = crate::native_api::NativeServer::start(api_listener, state);
    native.attach_for_test();
    let loop_state = UdpLoopState::new(&plane, false);
    let _held: Vec<_> = (0..2048)
        .map(|_| plane.dns_controller.try_admit_query(false).unwrap())
        .collect();

    let query = dns_query_payload();
    let work = begin_udp_dns_query(
        &plane.dns_controller,
        &plane.stats,
        DatagramPayload::Borrowed(&query),
        validate_exact_dns_query(&query).unwrap(),
        addr("127.0.0.1:40000"),
    );
    assert!(matches!(work, UdpSlowPathWork::DnsRefused { .. }));
    loop_state.spawn_work(addr("127.0.0.1:40000"), addr("127.0.0.1:53"), work);

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let steps = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let page: serde_json::Value = client
                .get(format!("http://{api_addr}/api/v1/flows"))
                .bearer_auth("refusal-flow-test")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if let Some(flow) = page["flows"]
                .as_array()
                .and_then(|flows| flows.first())
                .filter(|flow| flow["state"] == "closed")
            {
                let detail: serde_json::Value = client
                    .get(format!(
                        "http://{api_addr}/api/v1/flows/{}",
                        flow["id"].as_str().unwrap()
                    ))
                    .bearer_auth("refusal-flow-test")
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                break detail["trace"]["steps"].as_array().unwrap().clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(steps.iter().any(|step| {
        step["stage"] == "dns"
            && step["data"]["status"] == "rejected"
            && step["data"]["error"] == "admission_refused"
    }));
    api_server.shutdown().await;
}
