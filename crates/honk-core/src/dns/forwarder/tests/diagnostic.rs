use super::*;
use crate::dns::{
    outcome::{Provenance, RouteSource},
    planner::UpstreamTag,
    upstream_pool::UpstreamPool,
};
use honk_config::{
    dns::{DnsRequestAction, DnsUpstream},
    types::DnsProtocol,
};

async fn loopback_dns() -> (
    SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<u16>,
) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (calls, received) = tokio::sync::mpsc::unbounded_channel();
    let worker = tokio::spawn(async move {
        let mut wire = [0; 512];
        let mut answer = 1;
        while let Ok((length, peer)) = socket.recv_from(&mut wire).await {
            let query = &wire[..length];
            let (_, qtype) = parse_dns_question(query).unwrap();
            calls.send(qtype).unwrap();
            let mut response = query.to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&qtype.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&300u32.to_be_bytes());
            if qtype == 1 {
                response.extend_from_slice(&4u16.to_be_bytes());
                response.extend_from_slice(&[192, 0, 2, answer]);
            } else {
                response.extend_from_slice(&16u16.to_be_bytes());
                response.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
            }
            answer += 1;
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    (address, worker, received)
}

fn config_for(address: SocketAddr) -> DnsConfig {
    let mut config = DnsConfig {
        upstream: vec![DnsUpstream {
            name: "unreferenced".into(),
            address: address.to_string(),
            protocol: DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }],
        ..Default::default()
    };
    config.routing.request.fallback = DnsRequestAction::Reject;
    config
}

#[tokio::test]
async fn diagnostic_force_precedes_reject_and_bypass_preserves_cached_answer() {
    let (address, worker, mut calls) = loopback_dns().await;
    let config = config_for(address);
    let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
    let pool = Arc::new(UpstreamPool::new(&config.upstream, router.clone()).unwrap());
    let forwarder =
        Arc::new(DnsForwarder::new(pool, test_cache(), router).with_configured_upstreams(&config));
    let service = crate::dns::DnsService::with_forwarder(forwarder.clone());
    let normal = ResolveOptions {
        cache: CacheAccess::Normal,
        forced_upstream: Some(UpstreamTag::new("unreferenced").unwrap()),
    };
    let deadline = || tokio::time::Instant::now() + Duration::from_secs(2);
    let first = service
        .diagnostic("example.com.", &[1], &normal, deadline())
        .await
        .unwrap()
        .pop()
        .unwrap()
        .outcome
        .unwrap();
    assert_eq!(first.request_route().source, RouteSource::Forced);
    let identity = first.cache_entry_id().unwrap().to_owned();
    let bypass = ResolveOptions {
        cache: CacheAccess::Bypass,
        ..normal.clone()
    };
    let second = service
        .diagnostic("example.com.", &[1], &bypass, deadline())
        .await
        .unwrap()
        .pop()
        .unwrap()
        .outcome
        .unwrap();
    assert_ne!(first.answer_ips(), second.answer_ips());
    assert_eq!(second.cache_entry_id(), None);
    let third = service
        .diagnostic("example.com.", &[1], &normal, deadline())
        .await
        .unwrap()
        .pop()
        .unwrap()
        .outcome
        .unwrap();
    assert_eq!(third.provenance(), Provenance::Cache);
    assert_eq!(third.answer_ips(), first.answer_ips());
    assert_eq!(third.cache_entry_id(), Some(identity.as_str()));
    assert_eq!(
        [calls.try_recv().unwrap(), calls.try_recv().unwrap()],
        [1, 1]
    );
    assert!(calls.try_recv().is_err());
    assert_eq!(forwarder.refresh_task_count(), 0);
    let bad = ResolveOptions {
        cache: CacheAccess::Normal,
        forced_upstream: Some(UpstreamTag::new("missing").unwrap()),
    };
    assert!(matches!(
        service
            .diagnostic("example.com.", &[1], &bad, deadline())
            .await,
        Err(crate::dns::service::DiagnosticError::UnknownUpstream)
    ));
    worker.abort();
    let _ = worker.await;
    forwarder.shutdown_background_tasks().await;
}

#[tokio::test]
async fn diagnostic_bypass_and_force_propagate_to_preferred_sibling() {
    let (address, worker, mut calls) = loopback_dns().await;
    let mut config = config_for(address);
    config.strategy = DnsStrategy::PreferIpv4;
    let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
    let pool = Arc::new(UpstreamPool::new(&config.upstream, router.clone()).unwrap());
    let forwarder = Arc::new(
        DnsForwarder::new(pool, test_cache(), router)
            .with_strategy(config.strategy)
            .with_configured_upstreams(&config),
    );
    let service = crate::dns::DnsService::with_forwarder(forwarder.clone());
    let options = ResolveOptions {
        cache: CacheAccess::Bypass,
        forced_upstream: Some(UpstreamTag::new("unreferenced").unwrap()),
    };
    let answer = service
        .diagnostic(
            "example.com.",
            &[28],
            &options,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap()
        .pop()
        .unwrap()
        .outcome
        .unwrap();
    assert!(
        answer.answer_ips().is_empty(),
        "real preferred A suppresses AAAA"
    );
    assert_eq!(
        [calls.try_recv().unwrap(), calls.try_recv().unwrap()],
        [28, 1]
    );
    assert_eq!(forwarder.cache_service().await.len(), 0);
    assert_eq!(forwarder.active_flights(), 0);
    assert_eq!(forwarder.refresh_task_count(), 0);
    worker.abort();
    let _ = worker.await;
    forwarder.shutdown_background_tasks().await;
}

#[tokio::test]
async fn source_resolution_logs_real_ipv6_client_but_diagnostic_does_not() {
    let (address, worker, _calls) = loopback_dns().await;
    let mut config = config_for(address);
    config.strategy = DnsStrategy::Ipv4Only;
    config.routing.request.fallback = DnsRequestAction::Upstream("unreferenced".into());
    let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
    let pool = Arc::new(UpstreamPool::new(&config.upstream, router.clone()).unwrap());
    let forwarder = Arc::new(
        DnsForwarder::new(pool, test_cache(), router)
            .with_strategy(config.strategy)
            .with_configured_upstreams(&config),
    );
    let service = crate::dns::DnsService::with_forwarder(forwarder.clone());
    let api = Arc::new(crate::native_api::dns::DnsApi::new(
        "client-resolution".into(),
        true,
        std::sync::Weak::new(),
    ));
    service.attach_observer(Arc::downgrade(&api.recorder));
    let source: SocketAddr = "[2001:db8::1]:53123".parse().unwrap();
    let resolved = service
        .resolve_name_for_source("example.com", source)
        .await
        .unwrap();
    assert_eq!(resolved.ipv4.len(), 1);
    service
        .diagnostic(
            "example.com.",
            &[1],
            &ResolveOptions::default(),
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
    let page = api.log_for_test().page_for_test();
    let body = axum::body::to_bytes(page.into_body(), 262_144)
        .await
        .unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["total"], 1);
    assert_eq!(page["records"][0]["src"], "[2001:db8::1]:53123");
    assert_eq!(page["records"][0]["answers"][0]["data"], "192.0.2.1");
    worker.abort();
    let _ = worker.await;
    forwarder.shutdown_background_tasks().await;
}

#[tokio::test]
async fn diagnostic_bypass_ignores_negative_without_replacing_it_or_joining_flights() {
    let (address, worker, mut calls) = loopback_dns().await;
    let mut config = config_for(address);
    config.routing.request.fallback = DnsRequestAction::AsIs;
    let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
    let pool = Arc::new(UpstreamPool::new(&config.upstream, router.clone()).unwrap());
    let forwarder =
        Arc::new(DnsForwarder::new(pool, test_cache(), router).with_configured_upstreams(&config));
    let service = crate::dns::DnsService::with_forwarder(forwarder.clone());
    let query = build_dns_query("example.com", 1);
    let parsed =
        crate::dns::query::QueryContext::parse_with_profile(&query, IngressProfile::Api).unwrap();
    let tag = UpstreamTag::new("unreferenced").unwrap();
    let key = crate::dns::cache::CacheKey::new(
        &parsed,
        None,
        crate::dns::planner::RequestScope::Upstream(tag.clone()),
        crate::dns::cache::OperationKind::Resolve,
    );
    let cache = forwarder.cache_service().await;
    let revision = cache
        .put_negative_if_current(cache.publication_epoch(), key.clone(), 60, 3, None)
        .unwrap();
    let flight = crate::dns::singleflight::FlightKey::resolve(
        key.clone(),
        ResolveMode::Strict,
        &DnsStrategy::Both,
        1,
        DnsRequestMeta::EMPTY,
        Some(&tag),
    );
    let crate::dns::singleflight::FlightRole::Leader(_held) =
        forwarder.singleflight().acquire(flight)
    else {
        panic!("flight leader");
    };
    let bypass = ResolveOptions {
        cache: CacheAccess::Bypass,
        forced_upstream: Some(tag),
    };
    let answer = service
        .diagnostic(
            "example.com.",
            &[1],
            &bypass,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap()
        .pop()
        .unwrap()
        .outcome
        .unwrap();
    assert_eq!(
        answer.answer_ips(),
        ["192.0.2.1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(answer.cache_entry_id(), None);
    assert!(
        matches!(cache.lookup_exact(&key, true), crate::dns::cache::ExactLookup::Negative {hit, revision: current} if hit.rcode == 3 && current == revision)
    );
    assert_eq!(calls.try_recv().unwrap(), 1);
    assert!(calls.try_recv().is_err());
    assert_eq!(
        forwarder.active_flights(),
        1,
        "bypass did not join or supersede held writing flight"
    );
    worker.abort();
    let _ = worker.await;
    forwarder.shutdown_background_tasks().await;
}
