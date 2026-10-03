use super::*;
use crate::dns::{
    cache::DnsCache,
    forwarder::{DnsForwarder, DnsUpstreamPool, parse_dns_question},
    routing::DnsRouter,
    runtime::{
        DnsRuntime, DnsRuntimeParts, RoutingProjectionSnapshot, RuntimeGeneration, RuntimeTransport,
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct FamilyPool {
    refusal: bool,
    response_code: u8,
    ipv6_queries: AtomicUsize,
}

#[async_trait::async_trait]
impl DnsUpstreamPool for FamilyPool {
    async fn query(&self, _: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match parse_dns_question(query).unwrap().1 {
            1 => {
                let error = if self.refusal {
                    std::io::Error::from(honk_outbound::proxy::PacketRejection::Capacity)
                } else {
                    std::io::ErrorKind::ConnectionRefused.into()
                };
                Err(anyhow::Error::new(error).context("A lookup failed"))
            }
            28 => {
                self.ipv6_queries.fetch_add(1, Ordering::SeqCst);
                let mut answer = query.to_vec();
                answer[2..4]
                    .copy_from_slice(&(0x8180 | u16::from(self.response_code)).to_be_bytes());
                answer[6..8].copy_from_slice(&1u16.to_be_bytes());
                answer.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                answer.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
                Ok(answer)
            }
            qtype => panic!("unexpected query type {qtype}"),
        }
    }
}

#[async_trait::async_trait]
impl RuntimeTransport for FamilyPool {
    async fn close(&self) {}
}

async fn family_preparation(refusal: bool, response_code: u8) {
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let node = Node::from_share_link(&format!(
        "socks5://probe.example:{}",
        listener.local_addr().unwrap().port(),
    ))
    .unwrap();
    let node_id = node.id;
    let mut config = Config::default();
    config.nodes.push(node);
    let state = state(config).await;
    let pool = Arc::new(FamilyPool {
        refusal,
        response_code,
        ipv6_queries: AtomicUsize::new(0),
    });
    let forwarder = Arc::new(DnsForwarder::new(
        pool.clone(),
        Arc::new(tokio::sync::Mutex::new(DnsCache::new(8))),
        Arc::new(DnsRouter::new_from_dns_config(&honk_config::dns::DnsConfig::default()).unwrap()),
    ));
    let provider = state.dns.provider().unwrap();
    let generation = provider.current_generation().get() + 1;
    provider.publish(DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(generation),
        udp_query_limit: 256,
        forwarder,
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            generation,
            Arc::new(crate::routing::Router::new(&[], "direct").unwrap()),
        )),
        outbound_runtime: None,
        transport: pool.clone(),
    }));
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let input = request(
        json!({"type":"node","node_id":node_id.to_string()}),
        "tcp_connect",
        json!(["tcp"]),
        "any",
    );
    let response = create(
        &state,
        http_request(&input, "family"),
        &RequestId("family".into()),
    )
    .await;
    let accepted = body(response.unwrap()).await;
    let result = terminal(&state, accepted["operation_id"].as_str().unwrap()).await;
    if refusal {
        assert_eq!(result["status"], "failed");
        assert_eq!(result["error"]["code"], "unsupported_value");
        assert_eq!(result["result"], Value::Null);
    } else {
        assert_eq!(
            result["result"]["results"][0]["error"],
            "address_unavailable"
        );
        assert_eq!(result["result"]["results"][0]["health_updated"], false);
        if response_code == 0 {
            assert_eq!(result["result"]["results"][1]["state"], "healthy");
            assert_eq!(result["result"]["results"][1]["health_updated"], true);
            let (mut socket, peer) =
                tokio::time::timeout(Duration::from_secs(1), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            assert!(peer.is_ipv6());
            assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
        } else {
            assert_eq!(
                result["result"]["results"][1]["error"],
                "address_unavailable"
            );
            assert_eq!(result["result"]["results"][1]["health_updated"], false);
        }
    }
    stop.send(true).unwrap();
    worker.await.unwrap();
    assert_eq!(pool.ipv6_queries.load(Ordering::SeqCst), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let observations = state.alive_set.health_observations(node_id);
    if refusal || response_code != 0 {
        assert!(
            observations.is_empty(),
            "unusable DNS answers cannot publish health"
        );
    } else {
        assert!(observations.iter().any(
            |sample| sample.ip_version == IpVersion::V6 && sample.state == HealthState::Healthy
        ));
        assert!(
            !observations
                .iter()
                .any(|sample| sample.ip_version == IpVersion::V4)
        );
    }
    provider.shutdown().await;
}

#[tokio::test]
async fn typed_dns_refusal_blocks_usable_sibling_before_dial_or_health() {
    family_preparation(true, 0).await;
}

#[tokio::test]
async fn ordinary_dns_failure_keeps_usable_sibling_and_skips_missing_family() {
    family_preparation(false, 0).await;
}

#[tokio::test]
async fn negative_dns_answer_addresses_cannot_admit_a_probe() {
    family_preparation(false, 3).await;
}
