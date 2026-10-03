//! The #280 policy shape: two `sip && dip && dport` rules ahead of fifteen
//! process-name rules, MAC rules between and after them, and later source,
//! destination and domain rules that keep every fact in use until the end.
//!
//! With facts kept as map pointers the verifier could not merge the paths
//! through the process-name chains and this policy exceeded the
//! 1,000,000-instruction budget on Linux 6.12. This test checks publication
//! and complete decisions, not a particular processed-instruction count.

use super::{assert_route, decision, domain_entry, input, object, outbound_ids};
use crate::control::routing_matcher::RoutingPushPlan;
use crate::ebpf::EbpfBackend;
use crate::ebpf::real::RealEbpfBackend;
use crate::routing::{Router, golden};
use honk_config::types::DialMode;
use honk_ebpf_common::DaeParam;

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn facts_ahead_of_long_process_chains_stay_within_the_verifier_budget() {
    let config = honk_config::parser::parse_dae_config(
        r#"
        routing {
            sip(198.18.81.2/32) && dip(198.18.80.2/32) && dport(15201) -> proxy(must)
            sip(198.18.81.2/32) && dip(198.18.80.2/32) && dport(15202) -> proxy(must)
            pname(dnsmasq, systemd-resolved) && l4proto(udp) && dport(53) -> block(must)
            pname(mosdns, honk-subsribe, honk-tool) -> block(must)
            pname(NetworkManager) -> block(must)
            pname(systemd-networkd) -> block(must)
            pname(systemd-resolved) -> block(must)
            pname(dhcpcd) -> block(must)
            mac(02:00:00:00:00:01, 02:00:00:00:00:02, 02:00:00:00:00:03, 02:00:00:00:00:04) -> block(must)
            mac(02:00:00:00:00:05) -> block(must)
            dscp(4) -> block(must)
            pname(qbittorrent) -> block(must)
            pname(iris) -> block(must)
            pname(iris-meta) -> block(must)
            pname(sing-box) -> block(must)
            pname(mihomo) -> block(must)
            pname(frpc) -> block(must)
            pname(einat) -> block(must)
            pname(qemu-system-x86) -> block(must)
            pname(pacman) -> block(must)
            mac(02:00:00:00:00:06) -> block(must)
            sip(198.51.100.24/32) && !dport(53) -> block(must)
            dip(10.0.0.0/8, 192.168.0.0/16) -> block(must)
            domain(suffix: example.net, suffix: example.org) -> block
            dport(14588) -> block(must)
            dip(203.0.113.0/24) -> proxy
            domain(suffix: example.com) -> proxy
            dport(22, 80, 443, 8080) -> proxy
            fallback: direct
        }
        "#,
    )
    .unwrap();
    let router = Router::new(&config.routing.rules, "direct").unwrap();
    let mut plan = RoutingPushPlan::compile(&router, &outbound_ids(), DialMode::Domain).unwrap();

    let mut benchmark = golden::connection();
    benchmark.src_ip = "198.18.81.2".parse().unwrap();
    benchmark.dst_ip = "198.18.80.2".parse().unwrap();
    benchmark.dst_port = 15201;
    let mut torrent = golden::connection();
    torrent.process_name = Some("qbittorrent".into());
    let mut lan = golden::connection();
    lan.mac = Some("02:00:00:00:00:06".into());
    let mut private = golden::connection();
    private.dst_ip = "192.168.7.7".parse().unwrap();
    let mut proxied = golden::connection();
    proxied.domain = Some("www.example.com".into());
    proxied.dst_ip = "203.0.113.9".parse().unwrap();
    let mut fallback = golden::connection();
    fallback.dst_port = 9999;

    let learned = [domain_entry(&router, &proxied, "www.example.com")];
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
    for enabled in [false, true] {
        plan.enable_trace(enabled);
        backend.publish_routing_plan(&plan, &learned).unwrap();

        for (label, connection, expected) in [
            ("first rule", &benchmark, decision(2, 0, true, 0, 0)),
            ("process name", &torrent, decision(1, 0, true, 0, 11)),
            ("MAC after the chains", &lan, decision(1, 0, true, 0, 20)),
            (
                "destination after the chains",
                &private,
                decision(1, 0, true, 0, 22),
            ),
            (
                "region with a learned domain",
                &proxied,
                decision(2, 0, false, 1, 25),
            ),
            ("fallback", &fallback, decision(0, 0, false, 0, u32::MAX)),
        ] {
            assert_route(&mut backend, label, &input(connection), expected);
        }
    }
}
