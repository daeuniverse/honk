use super::*;
use crate::dns::{
    DnsService,
    cache::DnsCache,
    forwarder::{DnsForwarder, build_dns_query},
    routing::DnsRouter,
    upstream_pool::UpstreamPool,
};
use crate::native_api::events::EventHub;
use crate::observe::flows::{FlowGuard, FlowStore};
use honk_config::{
    dns::{DnsCond, DnsConfig, DnsRequestAction, DnsRequestRule, DnsUpstream},
    types::DnsProtocol,
};
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};

struct Unrecorded;

impl crate::observe::DnsLog for Unrecorded {
    fn recording(&self) -> bool {
        false
    }

    fn capture(
        &self,
        _: &[u8],
        _: IngressProfile,
        _: Option<SocketAddr>,
        _: Option<&DnsOutcome>,
        _: &[u8],
        _: Duration,
    ) {
    }
}

fn recorder(instance: String, store: &Arc<FlowStore>) -> Arc<DnsRecorder> {
    Arc::new(DnsRecorder::new(
        instance,
        Arc::downgrade(store),
        Arc::new(Unrecorded),
    ))
}

async fn fixture() -> (
    DnsService,
    Arc<FlowStore>,
    Arc<DnsRecorder>,
    Arc<Semaphore>,
    mpsc::UnboundedReceiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let gate = Arc::new(Semaphore::new(0));
    let send_gate = gate.clone();
    let (calls, received) = mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        let mut wire = [0; 512];
        loop {
            let (length, peer) = socket.recv_from(&mut wire).await.unwrap();
            let mut response = wire[..length].to_vec();
            calls.send(()).unwrap();
            send_gate.acquire().await.unwrap().forget();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 17]);
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let mut config = DnsConfig {
        upstream: vec![DnsUpstream {
            name: "loopback".into(),
            address: address.to_string(),
            protocol: DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }],
        ..Default::default()
    };
    config.routing.request.rules = vec![
        DnsRequestRule {
            conditions: vec![DnsCond::Qtype {
                not: false,
                types: vec![28],
            }],
            action: DnsRequestAction::Reject,
        },
        DnsRequestRule {
            conditions: vec![DnsCond::Sip {
                not: false,
                cidrs: vec!["127.0.0.0/8".into()],
            }],
            action: DnsRequestAction::Upstream("loopback".into()),
        },
    ];
    config.routing.request.fallback = DnsRequestAction::Upstream("loopback".into());
    let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
    let pool = Arc::new(UpstreamPool::new(&config.upstream, router.clone()).unwrap());
    let forwarder = Arc::new(DnsForwarder::new(
        pool,
        Arc::new(tokio::sync::Mutex::new(DnsCache::new(64))),
        router,
    ));
    let service = DnsService::with_forwarder(forwarder);
    let instance = Uuid::new_v4().to_string();
    let store = Arc::new(FlowStore::new(
        instance.clone(),
        Arc::new(EventHub::new(instance.clone())),
    ));
    let api = recorder(instance, &store);
    service.attach_observer(Arc::downgrade(&api));
    (service, store, api, gate, received, server)
}

fn observer(store: &Arc<FlowStore>) -> (Arc<FlowGuard>, FlowObserver) {
    let flow = Arc::new(
        store
            .begin(
                crate::observe::vocab::Network::Tcp,
                "127.0.0.1:31000".parse().unwrap(),
                "192.0.2.17:443".parse().unwrap(),
            )
            .unwrap(),
    );
    let observer = flow.observer(7, None, "dial_target").unwrap();
    (flow, observer)
}

fn detail(store: &FlowStore, flow: &FlowGuard) -> serde_json::Value {
    store.get(flow.id()).unwrap()
}
fn dns_rows(detail: &serde_json::Value) -> Vec<&serde_json::Value> {
    detail["trace"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["stage"] == "dns")
        .map(|step| &step["data"])
        .collect()
}

#[tokio::test]
async fn source_policy_cache_and_verification_ignore_dns_log_toggle() {
    let (service, store, api, gate, mut calls, server) = fixture().await;
    let (flow, observer) = observer(&store);
    gate.add_permits(1);
    let query = build_dns_query("proof.example", 1);
    observer
        .scope(scope_purpose(
            "domain_verification",
            std::pin::pin!(service.resolve_with_context(
                &query,
                DnsRequestMeta::new(Some("127.0.0.1".parse().unwrap()), None),
                IngressProfile::Internal,
            )),
        ))
        .await
        .unwrap();
    calls.recv().await.unwrap();
    observer
        .scope(service.resolve_with_context(
            &query,
            DnsRequestMeta::new(Some("127.0.0.1".parse().unwrap()), None),
            IngressProfile::Internal,
        ))
        .await
        .unwrap();
    let rejected = observer
        .scope(service.resolve(
            &build_dns_query("proof.example", 28),
            IngressProfile::Internal,
        ))
        .await
        .unwrap();
    assert_eq!(rejected[6..8], [0, 0]);
    assert!(calls.try_recv().is_err());
    assert!(!api.recording());
    let view = detail(&store, &flow);
    let rows = dns_rows(&view);
    assert!(
        rows.iter()
            .any(|row| row["purpose"] == "domain_verification"
                && row["status"] == "succeeded"
                && row["addresses"][0] == "192.0.2.17")
    );
    assert!(
        rows.iter()
            .any(|row| row["source"] == "cache" && row["cache"] == "hit")
    );
    assert!(rows.iter().any(|row| row["status"] == "rejected"
        && row["qtype"] == "AAAA"
        && row["cache"] == "bypass"));
    assert!(rows.iter().all(|row| row["selected_ip"].is_null()));
    let route = view["trace"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["data"]["chain"] == "dns_request")
        .unwrap();
    assert_eq!(
        route["data"]["rules"][0]["conditions"][0]["result"],
        "not_matched"
    );
    assert_eq!(
        route["data"]["rules"][1]["conditions"][0]["result"],
        "matched"
    );
    assert_eq!(route["data"]["input"]["source_ip"], "127.0.0.1");
    assert_eq!(route["data"]["dns_action"], "upstream");
    let response_route = view["trace"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["data"]["chain"] == "dns_response")
        .unwrap();
    assert_eq!(response_route["data"]["input"]["from_upstream"], "loopback");
    assert_eq!(
        response_route["data"]["input"]["answer_ips"][0],
        "192.0.2.17"
    );
    assert_eq!(response_route["data"]["dns_action"], "accept");
    service
        .resolve_with_context(
            &query,
            DnsRequestMeta::new(Some("127.0.0.1".parse().unwrap()), None),
            IngressProfile::Internal,
        )
        .await
        .unwrap();
    assert_eq!(
        detail(&store, &flow)["trace"]["steps"],
        view["trace"]["steps"]
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn coalesced_consumers_keep_own_lineage_and_cancelled_lookup_resolves() {
    let (service, store, _api, gate, mut calls, server) = fixture().await;
    let (first_flow, first) = observer(&store);
    let (second_flow, second) = observer(&store);
    let first_service = service.clone();
    let leader = tokio::spawn(async move {
        first
            .scope(first_service.resolve(
                &build_dns_query("shared.example", 1),
                IngressProfile::Internal,
            ))
            .await
    });
    calls.recv().await.unwrap();
    let second_service = service.clone();
    let follower = tokio::spawn(async move {
        second
            .scope(second_service.resolve(
                &build_dns_query("shared.example", 1),
                IngressProfile::Internal,
            ))
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if dns_rows(&detail(&store, &second_flow))
                .iter()
                .any(|row| row["status"] == "started")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // A source-owned join marker is emitted before waiting, so no scheduler delay is assumed.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if dns_rows(&detail(&store, &second_flow))
                .iter()
                .any(|row| row["source"] == "coalesced")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    gate.add_permits(1);
    leader.await.unwrap().unwrap();
    follower.await.unwrap().unwrap();
    assert!(calls.try_recv().is_err());
    let first_view = detail(&store, &first_flow);
    let second_view = detail(&store, &second_flow);
    assert!(
        dns_rows(&first_view)
            .iter()
            .any(|row| row["upstream_transport"] == "udp" && row["status"] == "succeeded")
    );
    assert!(
        dns_rows(&second_view)
            .iter()
            .any(|row| row["source"] == "coalesced" && row["status"] == "succeeded")
    );
    assert!(
        dns_rows(&second_view)
            .iter()
            .all(|row| row["parent_lookup_id"].is_null())
    );
    let (cancelled_flow, cancelled) = observer(&store);
    let task = tokio::spawn(async move {
        cancelled
            .scope(service.resolve(
                &build_dns_query("cancel.example", 1),
                IngressProfile::Internal,
            ))
            .await
    });
    calls.recv().await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        dns_rows(&detail(&store, &cancelled_flow))
            .iter()
            .any(|row| row["status"] == "cancelled")
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn foreign_dns_sink_cannot_publish_unresolved_rule_references() {
    let (service, store, _api, gate, mut calls, server) = fixture().await;
    let other_instance = Uuid::new_v4().to_string();
    let other_store = Arc::new(FlowStore::new(
        other_instance.clone(),
        Arc::new(EventHub::new(other_instance.clone())),
    ));
    let foreign_api = recorder(other_instance, &other_store);
    service.attach_observer(Arc::downgrade(&foreign_api));
    let (flow, observer) = observer(&store);
    gate.add_permits(1);
    observer
        .scope(service.resolve(
            &build_dns_query("foreign.example", 1),
            IngressProfile::Internal,
        ))
        .await
        .unwrap();
    calls.recv().await.unwrap();
    let view = detail(&store, &flow);
    assert!(
        dns_rows(&view)
            .iter()
            .all(|row| row["route_evaluation_ids"].as_array().unwrap().is_empty())
    );
    assert!(
        view["trace"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["stage"] != "route")
    );
    assert!(
        view["trace"]["missing"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason == "not_instrumented")
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn suppressed_resolution_cannot_mutate_the_parent_lookup() {
    let (service, store, _api, gate, mut calls, server) = fixture().await;
    let (flow, observer) = observer(&store);
    let query = build_dns_query("parent.example", 1);
    gate.add_permits(1);
    observer
        .scope(client_scope(
            &query,
            IngressProfile::Internal,
            DnsRequestMeta::EMPTY,
            std::pin::pin!(async {
                flow_observation::without(service.resolve(
                    &build_dns_query("background.example", 1),
                    IngressProfile::Internal,
                ))
                .await
                .unwrap();
            }),
        ))
        .await;
    calls.recv().await.unwrap();
    let view = detail(&store, &flow);
    let rows = dns_rows(&view);
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| row["name"] == "parent.example" && row["source"] == "unknown")
    );
    assert!(
        rows.iter()
            .all(|row| row["cache_entry_id"].is_null() && row["upstream"].is_null())
    );
    assert_eq!(rows[1]["status"], "failed");
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn selection_evidence_keeps_the_consumed_catalog_after_group_recreation() {
    use honk_outbound::{
        alive::{IpVersion, ProbeDomain},
        group::{GroupManager, ScoreSelectionContext, SelectionNetwork},
    };
    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    config.groups.push(honk_config::group::Group {
        name: "dns-root".into(),
        nodes: vec![
            honk_config::config::DIRECT_NODE_ID,
            honk_config::config::BLOCK_NODE_ID,
        ],
        ..Default::default()
    });
    let catalog = crate::observe::catalog::Catalog::new(&config);
    let consumed = catalog.snapshot();
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let mut removed = config.clone();
    removed.groups.clear();
    catalog.install_prepared(catalog.prepare(&removed));
    catalog.install_prepared(catalog.prepare(&config));
    assert_ne!(
        consumed.groups["dns-root"],
        catalog.snapshot().groups["dns-root"]
    );
    let instance = Uuid::new_v4().to_string();
    let store = Arc::new(FlowStore::new(
        instance.clone(),
        Arc::new(EventHub::new(instance.clone())),
    ));
    let api = recorder(instance, &store);
    let (flow, observer) = observer(&store);
    scope_api(
        Arc::downgrade(&api),
        scope_catalog(
            Some(consumed.clone()),
            observer.scope(async {
                let plan = observer.sync_scope(|| {
                    manager.selection_plan_for_target_with_health_fallback(
                        "dns-root",
                        &ScoreSelectionContext {
                            network: SelectionNetwork::Tcp,
                            probe_domain: ProbeDomain::Tcp,
                            target_family: Some(IpVersion::V4),
                            health_family: IpVersion::V4,
                            target: None,
                        },
                        None,
                    )
                });
                let rows = selection_evaluated(plan.observation.as_deref());
                assert_eq!(rows[0].group_id, consumed.groups["dns-root"]);
                let picked = plan.entries.first().unwrap();
                let path = selection_path(
                    &rows,
                    &picked.selection_chain,
                    picked.node,
                    plan.health_family,
                );
                assert_eq!(
                    path[0].member_id.as_deref(),
                    Some(picked.node.id.to_string().as_str())
                );
            }),
        ),
    )
    .await;
    let view = detail(&store, &flow);
    let decision = view["trace"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["data"]["reason"] == "selection_evaluated")
        .unwrap();
    assert_eq!(
        decision["data"]["selections"][0]["group_id"],
        consumed.groups["dns-root"]
    );
    assert!(
        decision["data"]["selections"][0]["selection"]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["member_id"]
                == honk_config::config::DIRECT_NODE_ID.to_string())
    );
}

#[tokio::test]
async fn tcp_wire_retry_keeps_distinct_lookup_ids_and_physical_parentage() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for cancel in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (second_sent, second_received) = tokio::sync::oneshot::channel();
        let (reply, wait_reply) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut first_query = vec![0; usize::from(first.read_u16().await.unwrap())];
            first.read_exact(&mut first_query).await.unwrap();
            drop(first);
            let (mut second, _) = listener.accept().await.unwrap();
            let mut second_query = vec![0; usize::from(second.read_u16().await.unwrap())];
            second.read_exact(&mut second_query).await.unwrap();
            second_sent.send(()).unwrap();
            if wait_reply.await.is_ok() {
                let mut answer = second_query.clone();
                answer[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                answer[6..8].copy_from_slice(&1u16.to_be_bytes());
                answer
                    .extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 17]);
                second.write_u16(answer.len() as u16).await.unwrap();
                second.write_all(&answer).await.unwrap();
            }
            (first_query, second_query)
        });
        let mut config = DnsConfig {
            upstream: vec![DnsUpstream {
                name: "retry".into(),
                address: address.to_string(),
                protocol: DnsProtocol::Tcp,
                tls_server_name: None,
                outbound: None,
            }],
            ..Default::default()
        };
        config.routing.request.fallback = DnsRequestAction::Upstream("retry".into());
        let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
        let pool = Arc::new(
            UpstreamPool::new(&config.upstream, router.clone())
                .unwrap()
                .with_timeouts(Duration::from_secs(2), Duration::from_secs(2)),
        );
        let service = DnsService::with_forwarder(Arc::new(DnsForwarder::new(
            pool.clone(),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(64))),
            router,
        )));
        let instance = Uuid::new_v4().to_string();
        let store = Arc::new(FlowStore::new(
            instance.clone(),
            Arc::new(EventHub::new(instance.clone())),
        ));
        let api = recorder(instance, &store);
        service.attach_observer(Arc::downgrade(&api));
        let (flow, observer) = observer(&store);
        let resolve = tokio::spawn(async move {
            observer
                .scope(service.resolve(
                    &build_dns_query("retry.example", 1),
                    IngressProfile::Internal,
                ))
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), second_received)
            .await
            .unwrap()
            .unwrap();
        if cancel {
            resolve.abort();
            assert!(resolve.await.unwrap_err().is_cancelled());
            drop(reply);
        } else {
            reply.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), resolve)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        let (first_query, second_query) = server.await.unwrap();
        assert_eq!(first_query, second_query);
        let view = detail(&store, &flow);
        let steps = view["trace"]["steps"].as_array().unwrap();
        let leaf = steps
            .iter()
            .find(|step| {
                step["stage"] == "outbound"
                    && step["data"]["kind"] == "leaf"
                    && step["data"]["status"] == "started"
            })
            .unwrap();
        let leaf_id = &leaf["data"]["attempt_id"];
        let logical_lookup = &leaf["data"]["lookup_id"];
        assert!(logical_lookup.is_string());
        let attempts: Vec<_> = steps
            .iter()
            .filter(|step| {
                step["stage"] == "dns"
                    && step["data"]["parent_lookup_id"] == *logical_lookup
                    && step["data"]["attempt_id"] == *leaf_id
                    && step["data"]["status"] != "started"
            })
            .collect();
        assert_eq!(attempts.len(), 2, "{view:#}");
        assert_ne!(
            attempts[0]["data"]["lookup_id"],
            attempts[1]["data"]["lookup_id"]
        );
        assert_eq!(attempts[0]["data"]["status"], "failed");
        assert_eq!(
            attempts[1]["data"]["status"],
            if cancel { "cancelled" } else { "succeeded" }
        );
        for attempt in &attempts {
            assert_eq!(attempt["data"]["cache"], "bypass");
            assert_eq!(attempt["data"]["source"], "upstream");
            assert_eq!(attempt["data"]["upstream"], "retry");
            assert_eq!(attempt["data"]["upstream_transport"], "tcp");
            assert_eq!(attempt["generation_id"], leaf["generation_id"]);
            let physical: Vec<_> = steps
                .iter()
                .filter(|step| {
                    step["stage"] == "outbound"
                        && step["data"]["kind"] == "transport"
                        && step["data"]["lookup_id"] == attempt["data"]["lookup_id"]
                })
                .collect();
            assert_eq!(physical.len(), 2, "{view:#}");
            assert_eq!(physical[0]["data"]["status"], "started");
            assert_eq!(physical[1]["data"]["status"], "succeeded");
            assert_eq!(
                physical[0]["data"]["attempt_id"],
                physical[1]["data"]["attempt_id"]
            );
            assert!(
                physical
                    .iter()
                    .all(|step| step["data"]["parent_attempt_id"] == *leaf_id
                        && step["generation_id"] == leaf["generation_id"])
            );
        }
        pool.close().await;
    }
}

#[tokio::test]
async fn non_utf8_query_cannot_claim_complete_trace() {
    let (service, store, _api, _gate, mut calls, server) = fixture().await;
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(&[1, 0xff, 0]);
    query.extend_from_slice(&[0, 1, 0, 1]);
    let (flow, observer) = observer(&store);
    assert!(
        observer
            .scope(service.resolve(&query, IngressProfile::Internal))
            .await
            .is_err()
    );
    let view = detail(&store, &flow);
    assert_eq!(view["trace"]["status"], "partial");
    assert!(
        view["trace"]["missing"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason == "not_instrumented")
    );
    assert!(calls.try_recv().is_err());
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn dns_proxy_hostname_and_warm_tcp_keep_query_purpose_and_lineage() {
    use honk_config::node::{Node, OutboundConfig};
    use honk_config::types::NodeProtocol;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for proxied in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if proxied {
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..4], &[5, 1, 0, 1]);
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 53])
                    .await
                    .unwrap();
            }
            for _ in 0..2 {
                let mut answer = vec![0; usize::from(stream.read_u16().await.unwrap())];
                stream.read_exact(&mut answer).await.unwrap();
                answer[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                stream.write_u16(answer.len() as u16).await.unwrap();
                stream.write_all(&answer).await.unwrap();
            }
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        });
        let mut node = Node {
            name: "dns-proxy".into(),
            address: "localhost".into(),
            port: address.port(),
            outbound: OutboundConfig::from_protocol(NodeProtocol::Socks5),
            ..Default::default()
        };
        node.id = node.derive_id();
        let mut config = DnsConfig {
            upstream: vec![DnsUpstream {
                name: "wire".into(),
                address: if proxied {
                    "192.0.2.53:53".into()
                } else {
                    address.to_string()
                },
                protocol: DnsProtocol::Tcp,
                tls_server_name: None,
                outbound: proxied.then(|| node.name.clone()),
            }],
            ..Default::default()
        };
        config.routing.request.fallback = DnsRequestAction::Upstream("wire".into());
        let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
        let pool = Arc::new(
            UpstreamPool::new_with_proxy(
                &config.upstream,
                router.clone(),
                Some(Arc::new(
                    crate::proxy::ProxyRegistry::default_resolver().unwrap(),
                )),
                vec![node],
                Vec::new(),
            )
            .unwrap(),
        );
        let service = DnsService::with_forwarder(Arc::new(DnsForwarder::new(
            pool.clone(),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(64))),
            router,
        )));
        let instance = Uuid::new_v4().to_string();
        let store = Arc::new(FlowStore::new(
            instance.clone(),
            Arc::new(EventHub::new(instance.clone())),
        ));
        let api = recorder(instance, &store);
        service.attach_observer(Arc::downgrade(&api));
        for (index, name) in ["cold.example", "warm.example"].into_iter().enumerate() {
            let (flow, _) = observer(&store);
            let observation = flow.observer(7, None, "intercepted_query").unwrap();
            let query = build_dns_query(name, 1);
            let response = tokio::time::timeout(
                Duration::from_secs(3),
                observation.scope(service.resolve(&query, IngressProfile::Internal)),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(
                crate::dns::response::ResponseTemplate::check(
                    &QueryContext::parse(&query).unwrap(),
                    &response,
                )
                .is_ok()
            );
            let view = detail(&store, &flow);
            let rows = dns_rows(&view);
            assert!(
                rows.iter()
                    .filter(|row| row["name"] == name)
                    .all(|row| row["purpose"] == "intercepted_query")
            );
            let steps = view["trace"]["steps"].as_array().unwrap();
            let leaf = steps
                .iter()
                .find(|step| {
                    step["stage"] == "outbound"
                        && step["data"]["kind"] == "leaf"
                        && step["data"]["status"] == "started"
                })
                .unwrap();
            let exchange = rows
                .iter()
                .find(|row| {
                    row["parent_lookup_id"] == leaf["data"]["lookup_id"]
                        && row["attempt_id"] == leaf["data"]["attempt_id"]
                        && row["status"] == "succeeded"
                })
                .unwrap();
            if proxied && index == 0 {
                let lookups: Vec<_> = rows
                    .iter()
                    .filter(|row| row["name"] == "localhost")
                    .collect();
                assert!(
                    lookups.iter().any(|row| row["status"] == "succeeded"),
                    "{view:#}"
                );
                assert!(lookups.iter().all(|row| row["purpose"] == "proxy_server"
                    && row["attempt_id"] == leaf["data"]["attempt_id"]
                    && row["parent_lookup_id"] == exchange["lookup_id"]));
            } else {
                assert!(rows.iter().all(|row| row["purpose"] != "proxy_server"));
            }
            let physical: Vec<_> = steps
                .iter()
                .filter(|step| step["stage"] == "outbound" && step["data"]["kind"] == "transport")
                .collect();
            let attachments: Vec<_> = steps
                .iter()
                .filter(|step| step["data"]["reason"] == "dns_transport_attached")
                .collect();
            if index == 0 {
                assert!(
                    physical
                        .iter()
                        .any(|step| step["data"]["status"] == "succeeded"),
                    "{view:#}"
                );
                assert!(attachments.is_empty(), "{view:#}");
            } else {
                assert!(physical.is_empty(), "{view:#}");
                assert_eq!(attachments.len(), 1, "{view:#}");
                assert_eq!(
                    attachments[0]["data"]["attempt_id"],
                    leaf["data"]["attempt_id"]
                );
                assert_eq!(attachments[0]["data"]["lookup_id"], exchange["lookup_id"]);
                assert_eq!(attachments[0]["generation_id"], leaf["generation_id"]);
                assert!(attachments[0]["data"]["server_addr"].is_null());
            }
            assert!(
                !steps
                    .iter()
                    .any(|step| step["data"]["reason"] == "target_confirmed"
                        || step["data"]["milestone"] == "first_reply")
            );
        }
        pool.close().await;
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn truncated_udp_keeps_both_wire_lookups_and_tcp_fallback_reason() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for malformed in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let socket = tokio::net::UdpSocket::bind(address).await.unwrap();
        let server = tokio::spawn(async move {
            let mut packet = [0; 512];
            let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
            let mut truncated = packet[..length].to_vec();
            truncated[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
            if malformed {
                // Question demux accepts this, but response validation must reject the missing RR.
                truncated[6..8].copy_from_slice(&1u16.to_be_bytes());
            }
            socket.send_to(&truncated, peer).await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut answer = vec![0; usize::from(stream.read_u16().await.unwrap())];
            stream.read_exact(&mut answer).await.unwrap();
            answer[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            stream.write_u16(answer.len() as u16).await.unwrap();
            stream.write_all(&answer).await.unwrap();
        });
        let mut config = DnsConfig {
            upstream: vec![DnsUpstream {
                name: "truncated".into(),
                address: address.to_string(),
                protocol: DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            }],
            ..Default::default()
        };
        config.routing.request.fallback = DnsRequestAction::Upstream("truncated".into());
        let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
        let pool = Arc::new(UpstreamPool::new(&config.upstream, router.clone()).unwrap());
        let service = DnsService::with_forwarder(Arc::new(DnsForwarder::new(
            pool.clone(),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(64))),
            router,
        )));
        let instance = Uuid::new_v4().to_string();
        let store = Arc::new(FlowStore::new(
            instance.clone(),
            Arc::new(EventHub::new(instance.clone())),
        ));
        let api = recorder(instance, &store);
        service.attach_observer(Arc::downgrade(&api));
        let (flow, observer) = observer(&store);
        let query = build_dns_query("truncated.example", 1);
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            observer.scope(service.resolve(&query, IngressProfile::Internal)),
        )
        .await
        .unwrap()
        .unwrap();
        let mut expected = query.clone();
        expected[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        assert_eq!(response, expected);
        let view = detail(&store, &flow);
        let steps = view["trace"]["steps"].as_array().unwrap();
        let (fallback_index, fallback) = steps
            .iter()
            .enumerate()
            .find(|(_, step)| step["data"]["reason"] == "dns_response_truncated_tcp_fallback")
            .unwrap();
        assert!(fallback["data"]["error"].is_null());
        assert_eq!(fallback["data"]["milestone"], "unknown");
        let rows = dns_rows(&view);
        let wires: Vec<_> = rows
            .iter()
            .copied()
            .filter(|row| row["attempt_id"].is_string() && row["status"] != "started")
            .collect();
        assert_eq!(wires.len(), 2, "{view:#}");
        let udp = wires[0];
        let tcp = wires[1];
        assert_eq!(udp["upstream_transport"], "udp");
        assert_eq!(
            udp["status"],
            if malformed { "failed" } else { "succeeded" }
        );
        if malformed {
            assert_eq!(udp["error"], "invalid_response");
        } else {
            assert!(udp["error"].is_null());
        }
        assert_eq!(tcp["upstream_transport"], "tcp");
        assert_eq!(tcp["status"], "succeeded");
        assert!(tcp["error"].is_null());
        assert_ne!(udp["lookup_id"], tcp["lookup_id"]);
        assert_ne!(udp["attempt_id"], tcp["attempt_id"]);
        assert_eq!(udp["parent_lookup_id"], tcp["parent_lookup_id"]);
        assert_eq!(tcp["parent_lookup_id"], fallback["data"]["lookup_id"]);
        assert_eq!(tcp["attempt_id"], fallback["data"]["attempt_id"]);
        for wire in wires {
            assert_eq!(wire["source"], "upstream");
            assert_eq!(wire["cache"], "bypass");
            assert!(wire["cache_entry_id"].is_null());
            assert_eq!(wire["upstream"], "truncated");
            assert_ne!(wire["lookup_id"], wire["parent_lookup_id"]);
            assert!(steps.iter().any(|step| step["stage"] == "outbound"
                && step["data"]["kind"] == "leaf"
                && step["data"]["status"] == "started"
                && step["data"]["attempt_id"] == wire["attempt_id"]
                && step["data"]["lookup_id"] == wire["parent_lookup_id"]));
            let physical: Vec<_> = steps
                .iter()
                .filter(|step| {
                    step["stage"] == "outbound"
                        && step["data"]["kind"] == "transport"
                        && step["data"]["lookup_id"] == wire["lookup_id"]
                })
                .collect();
            assert_eq!(physical.len(), 2, "{view:#}");
            assert_eq!(physical[0]["data"]["status"], "started");
            assert_eq!(physical[1]["data"]["status"], "succeeded");
            assert!(
                physical
                    .iter()
                    .all(|step| step["data"]["parent_attempt_id"] == wire["attempt_id"])
            );
            let wire_index = steps
                .iter()
                .position(|step| step["stage"] == "dns" && step["data"] == *wire)
                .unwrap();
            assert_eq!(
                wire_index < fallback_index,
                wire["upstream_transport"] == "udp"
            );
        }
        assert!(
            !steps
                .iter()
                .any(|step| step["data"]["reason"] == "target_confirmed"
                    || step["data"]["reason"] == "dns_transport_attached"
                    || step["data"]["milestone"] == "first_reply")
        );
        pool.close().await;
        server.await.unwrap();
    }
}
