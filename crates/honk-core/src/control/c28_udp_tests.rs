use super::*;
use crate::control::c20_tests::{canonical_socks5, control_plane};
use crate::control::drain::DrainTracker;
use honk_config::parser::parse_dae_config;
use honk_outbound::alive::{IpVersion, ProbeDomain, UdpProber};
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[tokio::test]
async fn c28_udp_reload_preserves_the_configured_probe_target() {
    for (old_raw, new_raw, expected_target, should_accept) in [
        (
            "127.0.0.1:5301",
            vec!["127.0.0.1:5302"],
            "127.0.0.1:5301",
            false,
        ),
        (
            "",
            vec!["8.8.8.8:53", "unused.example:5302"],
            "8.8.8.8:53",
            true,
        ),
        (
            "old.example:5301",
            vec!["new.example:5301"],
            "127.0.0.1:5301",
            false,
        ),
        (
            "OLD.example.:5301",
            vec!["old.example:5301"],
            "127.0.0.1:5301",
            true,
        ),
        (
            "127.0.0.1:5301",
            vec!["unused.example", " 127.0.0.1:5301 ", "127.0.0.1:5302"],
            "127.0.0.1:5301",
            true,
        ),
    ] {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&resolver_calls);
        let resolver: crate::outbound::ResolveHook = Arc::new(move |_host, port| {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { vec![SocketAddr::from(([127, 0, 0, 1], port))] })
        });
        let node = canonical_socks5("c28-udp", "127.0.0.1", 9, None);
        let mut config = Config::default();
        config.global.nfqueue_enable = false;
        config.global.udp_check_dns = vec![old_raw.into()];
        config.nodes = vec![node.clone()];
        let target =
            resolve_udp_check_target(&config.global.udp_check_dns, Some(resolver.clone())).await;
        let identity = udp_probe_identity(&config.global.udp_check_dns, target);
        let cp = control_plane(config.clone()).await;
        cp.alive_set().set_resolver(resolver);
        let calls_before = resolver_calls.load(Ordering::SeqCst);
        let capture = Arc::new(Mutex::new(None));
        let handler = Arc::new(UdpTestHandler {
            mode: UdpTestMode::DnsResponseCaptureTarget(Arc::clone(&capture)),
        });
        let mut registry = ProxyRegistry::new();
        registry.register(
            honk_outbound::proxy::ProtocolEntry::new(node.protocol(), handler.clone())
                .with_packet(handler),
        );
        let prober = crate::control::probers::ProxyUdpProber::new(
            cp.config_handle(),
            Arc::new(registry),
            cp.runtime_registry(),
            cp.stats_handle(),
            target,
            identity,
            None,
            cp.group_manager(),
        );
        let generation = cp.runtime_registry().read().generation();
        let mut candidate = config.clone();
        candidate.global.udp_check_dns = new_raw.into_iter().map(str::to_owned).collect();
        let accepted = cp
            .apply_runtime_config(candidate.clone(), Default::default(), &DrainTracker::new())
            .await;
        let outcome = UdpProber::probe_udp(&prober, &node.name, Duration::from_secs(1)).await;
        assert!(outcome.dns.is_ok(), "{outcome:?}");
        assert_eq!(
            *capture.lock(),
            Some(expected_target.parse::<SocketAddr>().unwrap()),
        );
        assert_eq!(resolver_calls.load(Ordering::SeqCst), calls_before);
        assert_eq!(accepted, should_accept, "configured UDP target: {old_raw}");
        assert_eq!(
            cp.config_handle().read().await.as_ref(),
            if should_accept { &candidate } else { &config },
        );
        if !should_accept {
            assert_eq!(cp.runtime_registry().read().generation(), generation);
        }
    }
}

fn dae_urltest_config(tolerance_ms: u64) -> Config {
    parse_dae_config(&format!(
        "global {{\n    nfqueue_enable: false\n    check_tolerance: {tolerance_ms}ms\n}}\n\
         node {{\n    a: 'socks5://127.0.0.1:1080'\n    b: 'socks5://127.0.0.1:1081'\n}}\n\
         group {{\n    url {{\n        filter: name('a')\n        filter: name('b')\n        policy: urltest\n    }}\n}}\n"
    ))
    .expect("valid dae URLTest fixture")
}

#[tokio::test]
async fn c28_dae_tolerance_reload_changes_real_urltest_selection() {
    let config = dae_urltest_config(100);
    let a_id = config
        .nodes
        .iter()
        .find(|node| node.name == "a")
        .unwrap()
        .id;
    let b_id = config
        .nodes
        .iter()
        .find(|node| node.name == "b")
        .unwrap()
        .id;
    let cp = super::super::c20_tests::control_plane(config).await;
    let alive = cp.alive_set();
    // Establish the incumbent through the real URLTest policy before the
    // challenger has a measurement.
    alive.record_probe_latency(
        a_id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    assert_eq!(
        cp.group_manager()
            .read()
            .select_node_for_domain("url", ProbeDomain::Tcp, IpVersion::V4)
            .unwrap()
            .name,
        "a"
    );
    // The challenger is now faster, but the old 100ms tolerance retains a.
    alive.record_probe_latency(
        b_id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(60),
    );
    assert_eq!(
        cp.group_manager()
            .read()
            .select_node_for_domain("url", ProbeDomain::Tcp, IpVersion::V4)
            .unwrap()
            .name,
        "a"
    );

    let candidate = dae_urltest_config(10);
    let accepted = cp
        .apply_runtime_config(candidate, Default::default(), &DrainTracker::new())
        .await;
    assert!(accepted, "dae tolerance-only reload must remain admissible");
    assert_eq!(
        cp.group_manager()
            .read()
            .select_node_for_domain("url", ProbeDomain::Tcp, IpVersion::V4)
            .unwrap()
            .name,
        "b",
        "the live URLTest policy must apply the adapted global tolerance"
    );
}
