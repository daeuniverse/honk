use super::*;
use crate::control::tests::support::NativeFlowApi;

#[tokio::test]
async fn native_udp_terminal_evidence_survives_retirement_and_tuple_reuse() {
    let api = NativeFlowApi::new().await;
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = client_socket.local_addr().unwrap();
    let dst = make_addr("127.0.0.1", 15353);
    let (removed_tx, mut removed_rx) = mpsc::channel(8);
    pool.set_remove_sink(removed_tx);
    let mut records = Vec::new();

    for (reason, state, reply) in [
        ("timeout_before_reply", "failed", false),
        ("reply_idle", "closed", true),
        ("transport_error", "failed", false),
        ("driver_cancelled", "failed", false),
        ("intentional_retirement", "closed", false),
        ("shutdown", "closed", false),
    ] {
        let flow = Arc::new(
            api.flows
                .begin(crate::observe::vocab::Network::Udp, client, dst)
                .unwrap(),
        );
        let id = flow.id().to_owned();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("retired tuple must allow a new initializer"),
        };
        lease.set_connection_guard(
            stats.track_connection("test-node", crate::stats::OutboundKind::Node),
        );
        let transport = Arc::new(ScriptedPacketTransport::with_receive_actions(
            dst,
            [if reason == "transport_error" {
                DriverSendAction::Error
            } else {
                DriverSendAction::Ok
            }],
            if reply {
                vec![DriverReceiveAction::Packet {
                    data: b"reply".to_vec(),
                    source: dst,
                }]
            } else {
                Vec::new()
            },
        ));
        let mut endpoint = UdpEndpoint::new(transport, dst, TEST_NODE_ID);
        endpoint.native.set_flow(Some(flow), &pool, None);
        let endpoint = Arc::new(endpoint);
        let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
        let death_called = Arc::new(AtomicBool::new(false));
        if reason == "transport_error" {
            let callback_pool = Arc::clone(&pool);
            let death_called = Arc::clone(&death_called);
            alive.set_death_callback(Some(Box::new(move |node, _| {
                death_called.store(true, Ordering::Relaxed);
                callback_pool.remove_by_node(node);
            })));
            for _ in 0..49 {
                alive.report_unavailable_traffic(
                    TEST_NODE_ID,
                    honk_outbound::alive::ProbeDomain::DataUdp,
                    honk_outbound::alive::IpVersion::V4,
                );
            }
        }
        let queue = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue,
            test_reply_socket().await,
            alive,
            Arc::clone(&stats),
            stats.outbound_tracker("test-node", crate::stats::OutboundKind::Node),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);
        let first = driver.wait_first_ack().await;
        if reason == "transport_error" {
            assert!(first.is_err());
            assert!(death_called.load(Ordering::Relaxed));
        } else {
            first.unwrap();
        }
        if reply {
            let mut bytes = [0; 16];
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(1), client_socket.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&bytes[..length], b"reply");
            tokio::time::timeout(Duration::from_secs(1), async {
                while !endpoint.has_reply() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            endpoint.mark_reply();
        }
        match reason {
            "timeout_before_reply" | "reply_idle" => {
                tokio::task::yield_now().await;
                tokio::time::pause();
                tokio::time::advance(REPLY_IDLE_TIMEOUT).await;
                recv_and_ack(&pool, &mut removed_rx).await.unwrap();
                tokio::time::resume();
            }
            "driver_cancelled" => {
                driver.abort();
                recv_and_ack(&pool, &mut removed_rx).await.unwrap();
            }
            "intentional_retirement" => {
                pool.remove(client, dst);
                recv_and_ack(&pool, &mut removed_rx).await.unwrap();
            }
            "shutdown" => {
                let shutting_pool = Arc::clone(&pool);
                let shutdown = tokio::spawn(async move { shutting_pool.shutdown().await });
                recv_and_ack(&pool, &mut removed_rx).await.unwrap();
                assert!(shutdown.await.unwrap().joined);
            }
            _ => {
                recv_and_ack(&pool, &mut removed_rx).await.unwrap();
            }
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while endpoint.ref_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(pool.is_empty());
        assert_eq!(stats.snapshot()["test-node"].active_conns, 0);
        let (upload, download) = endpoint.byte_counters();
        assert_eq!(
            upload.load(Ordering::Relaxed),
            if reason == "transport_error" { 0 } else { 5 }
        );
        assert_eq!(download.load(Ordering::Relaxed), if reply { 5 } else { 0 });
        records.push((id, reason, state, reply));
    }

    for (id, reason, state, reply) in records {
        let detail = api.detail(&id).await;
        assert_eq!(detail["state"], state);
        assert!(detail["ended_at"].is_string());
        let steps = detail["trace"]["steps"].as_array().unwrap();
        let terminal: Vec<_> = steps
            .iter()
            .filter(|step| step["data"]["milestone"] == "terminal")
            .collect();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0]["data"]["reason"], reason);
        assert_eq!(
            steps
                .iter()
                .filter(|step| step["data"]["milestone"] == "first_reply")
                .count(),
            usize::from(reply)
        );
    }
    api.shutdown().await;
}

#[tokio::test]
async fn native_udp_block_loser_does_not_close_direct_winner_with_sniffed_domain() {
    assert_native_udp_builtin_plan(false).await;
}

#[tokio::test]
async fn native_udp_selector_block_records_authoritative_terminal() {
    assert_native_udp_builtin_plan(true).await;
}

async fn assert_native_udp_builtin_plan(selector_block: bool) {
    use crate::control::tests::support::{UdpTestReplySocketFactory, test_dns_forwarder};
    use crate::native_api::{NativeServer, NativeState};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = listener.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = upstream.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let mut config = honk_config::Config::default();
    config.global.nfqueue_enable = false;
    config.global.store_subscribe = false;
    config.global.dial_mode = "domain+".into();
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.listen = api_addr.to_string();
    config.experimental.native_api.secret = "native-race-test".into();
    config.ensure_builtin_nodes();
    let block = config
        .nodes
        .iter()
        .find(|node| node.name == "block")
        .unwrap()
        .id;
    let direct = config
        .nodes
        .iter()
        .find(|node| node.name == "direct")
        .unwrap()
        .id;
    config.groups.push(honk_config::group::Group {
        name: "cold".into(),
        policy: if selector_block {
            honk_config::group::GroupPolicy::Selector
        } else {
            honk_config::group::GroupPolicy::URLTest
        },
        nodes: if selector_block {
            vec![block]
        } else {
            vec![block, direct]
        },
        ..Default::default()
    });
    config.routing.default_outbound = "cold".into();
    let router =
        crate::routing::Router::new(&config.routing.rules, &config.routing.default_outbound)
            .unwrap();
    let resolver = crate::dns::DnsResolver::new(&config.dns).unwrap();
    let mut control = crate::control::ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver().unwrap()),
        resolver,
        test_dns_forwarder(),
    )
    .unwrap();
    control.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        2,
        Arc::new(UdpTestReplySocketFactory),
    ));
    let state = Arc::new(
        NativeState::new(
            &mut control,
            api_addr,
            std::time::SystemTime::now(),
            Instant::now(),
        )
        .await
        .unwrap(),
    );
    state.observation.attach_for_test();
    let server = NativeServer::start(listener, state);
    let handle = control.spawn_handle();
    let hello = crate::control::quic::test_utils::build_client_hello(Some("original-target.test"));
    let packet = crate::control::quic::test_utils::protect_initial_packet(
        b"dcid1234",
        b"",
        1,
        0,
        1,
        &crate::control::quic::test_utils::wrap_crypto_frame(0, &hello),
    );
    let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let lease = match handle.udp_pool.reserve_or_enqueue(
        client_addr,
        destination,
        &packet,
        permit,
        &handle.stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("cold route must own a new initializer"),
    };
    tokio::time::timeout(Duration::from_secs(5), handle.serve_udp_connection(lease))
        .await
        .unwrap()
        .unwrap();
    let mut received = vec![0; packet.len() + 1];
    if !selector_block {
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut received))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&received[..length], packet.as_slice());
        let endpoint = handle.udp_pool.get(client_addr, destination).unwrap();
        assert_eq!(
            endpoint.byte_counters().0.load(Ordering::Relaxed),
            packet.len() as u64
        );
    } else {
        assert!(handle.udp_pool.is_empty());
        assert_eq!(
            upstream.try_recv_from(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(handle.stats.snapshot()["cold"].active_conns, 0);
        assert_eq!(handle.stats.snapshot()["cold"].errors, 0);
    }
    let flows: serde_json::Value = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{api_addr}/api/v1/flows"))
        .bearer_auth("native-race-test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(flows["flows"].as_array().unwrap().len(), 1);
    let rule_id = format!("{}:0:fallback", flows["instance_id"].as_str().unwrap());
    assert_eq!(flows["flows"][0]["rule_id"], rule_id);
    assert_eq!(flows["flows"][0]["rule_source"], "recomputed");
    let flow_id = flows["flows"][0]["id"].as_str().unwrap();
    let detail: serde_json::Value = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{api_addr}/api/v1/flows/{flow_id}"))
        .bearer_auth("native-race-test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["rule_id"], rule_id);
    assert_eq!(detail["rule_source"], "recomputed");
    assert_eq!(
        detail["state"],
        if selector_block { "blocked" } else { "active" }
    );
    if selector_block {
        assert!(detail["ended_at"].is_string());
    } else {
        assert_eq!(detail["ended_at"], serde_json::Value::Null);
    }
    assert_eq!(detail["input"]["domain"], "original-target.test");
    let steps = detail["trace"]["steps"].as_array().unwrap();
    let failed_block = steps
        .iter()
        .find(|step| {
            step["stage"] == "outbound"
                && step["data"]["leaf_node_id"] == block.to_string()
                && step["data"]["status"] == "failed"
        })
        .unwrap();
    assert_eq!(failed_block["data"]["target_kind"], "none");
    assert_eq!(failed_block["data"]["target"], serde_json::Value::Null);
    if selector_block {
        let terminal: Vec<_> = steps
            .iter()
            .filter(|step| step["data"]["milestone"] == "terminal")
            .collect();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0]["data"]["state"], "blocked");
        assert_eq!(terminal[0]["data"]["reason"], "policy_block");
        assert!(handle.udp_pool.shutdown().await.joined);
        server.shutdown().await;
        return;
    }
    let connections: serde_json::Value = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{api_addr}/api/v1/connections"))
        .bearer_auth("native-race-test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let connection = connections["udp"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["flow_id"] == flow_id)
        .unwrap();
    assert_eq!(connection["rule_id"], rule_id);
    assert_eq!(connection["rule_source"], "recomputed");
    let won_direct = steps
        .iter()
        .find(|step| {
            step["stage"] == "outbound"
                && step["data"]["leaf_node_id"] == direct.to_string()
                && step["data"]["status"] == "succeeded"
        })
        .unwrap();
    assert_eq!(won_direct["data"]["target_kind"], "ip");
    assert_eq!(won_direct["data"]["target"], destination.to_string());
    let winner = &won_direct["data"]["attempt_id"];
    assert!(
        steps
            .iter()
            .any(|step| step["data"]["reason"] == "udp_prepared"
                && step["data"]["attempt_id"] == *winner)
    );
    assert!(
        steps
            .iter()
            .any(|step| step["data"]["reason"] == "udp_transport_ready"
                && step["data"]["attempt_id"] == *winner)
    );
    assert!(
        steps
            .iter()
            .any(|step| step["data"]["reason"] == "application_send_accepted"
                && step["data"]["attempt_id"] == *winner)
    );
    assert!(
        steps
            .iter()
            .any(|step| step["data"]["reason"] == "selection_evaluated")
    );
    assert_eq!(
        steps
            .iter()
            .rfind(|step| step["stage"] == "dial_mode")
            .unwrap()["data"]["effective_target"],
        "ip"
    );
    assert!(
        !steps
            .iter()
            .any(|step| step["data"]["milestone"] == "terminal")
    );
    assert!(handle.udp_pool.shutdown().await.joined);
    server.shutdown().await;
}

#[tokio::test]
async fn native_udp_received_reply_survives_client_send_failure_until_cleanup() {
    let api = NativeFlowApi::new().await;
    for cleanup_succeeded in [true, false] {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let client = make_addr("127.0.0.1", 0);
        let flow = Arc::new(
            api.flows
                .begin(crate::observe::vocab::Network::Udp, client, destination)
                .unwrap(),
        );
        let id = flow.id().to_owned();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease =
            match pool.reserve_or_enqueue(client, destination, b"request", permit, &stats) {
                EndpointReservation::Initializing(lease) => lease,
                _ => panic!("new loopback flow must be admitted"),
            };
        let (removed_tx, mut removed_rx) = mpsc::channel(1);
        pool.set_remove_sink(removed_tx);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut endpoint =
            UdpEndpoint::new(transport(socket, destination), destination, TEST_NODE_ID);
        endpoint.native.set_flow(Some(flow), &pool, None);
        let endpoint = Arc::new(endpoint);
        let mut driver = pool.spawn_driver(
            client,
            destination,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            lease.take_queue_receiver().unwrap(),
            test_reply_socket().await,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            stats.outbound_tracker("loopback", crate::stats::OutboundKind::Node),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);
        driver.wait_first_ack().await.unwrap();
        let mut request = [0; 32];
        let (length, peer) = upstream.recv_from(&mut request).await.unwrap();
        assert_eq!(&request[..length], b"request");
        upstream.send_to(b"reply", peer).await.unwrap();
        let removal = tokio::time::timeout(Duration::from_secs(2), removed_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            !endpoint.has_reply(),
            "failed client delivery must remain Score-neutral RX"
        );
        assert_eq!(endpoint.byte_counters().1.load(Ordering::Relaxed), 0);
        let before = api.detail(&id).await;
        assert!(before["ended_at"].is_null());
        let steps = before["trace"]["steps"].as_array().unwrap();
        assert_eq!(
            steps
                .iter()
                .filter(|step| step["data"]["milestone"] == "first_reply")
                .count(),
            1
        );
        assert!(
            steps
                .iter()
                .any(|step| step["data"]["reason"] == "client_delivery_failed"
                    && step["data"]["action"] == "drop")
        );
        assert!(
            !steps
                .iter()
                .any(|step| step["data"]["reason"] == "client_delivery_succeeded")
        );
        drop(endpoint);
        assert!(pool.wait_removal_io(&removal).await);
        pool.finish_removal(&removal, cleanup_succeeded);
        let after = api.detail(&id).await;
        let terminal: Vec<_> = after["trace"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|step| step["data"]["milestone"] == "terminal")
            .collect();
        assert_eq!(terminal.len(), 1);
        assert_eq!(
            terminal[0]["data"]["reason"],
            if cleanup_succeeded {
                "client_delivery_failed"
            } else {
                "cleanup_failed"
            }
        );
        if !cleanup_succeeded {
            assert!(pool.complete_removal(
                removal.client,
                removal.dst,
                removal.decision_token,
                removal.generation
            ));
        }
        assert!(pool.shutdown().await.joined);
    }
    api.shutdown().await;
}

#[tokio::test]
async fn native_udp_queued_packet_cannot_borrow_recreated_token_zero_witness() {
    use crate::control::tests::support::{UdpTestReplySocketFactory, control_plane};
    use crate::ebpf::{EbpfBackend, mock::MockEbpfBackend};
    use honk_ebpf_common::*;
    for recreated in [false, true] {
        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_addr = api_listener.local_addr().unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let mut config = honk_config::Config::default();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.global.dial_mode = "ip".into();
        config.routing.default_outbound = "direct".into();
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.secret = "udp-lineage-test".into();
        config.experimental.native_api.listen = api_addr.to_string();
        config.ensure_builtin_nodes();
        let router = crate::routing::Router::new(&[], "direct").unwrap();
        let mut plan = crate::control::routing_matcher::RoutingPushPlan::compile(
            &router,
            &std::collections::HashMap::from([("direct".into(), 0), ("block".into(), 1)]),
            honk_config::types::DialMode::Ip,
        )
        .unwrap();
        plan.enable_trace(true);
        let mut plane = control_plane(config.clone());
        plane.diagnostics.write().generation = 17;
        plane.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
            2,
            Arc::new(UdpTestReplySocketFactory),
        ));
        let native = crate::native_api::observation::NativeObservation::attach(&mut plane).await;
        native.attach_for_test();
        let state = Arc::new(
            crate::native_api::NativeState::with_observation(
                &mut plane,
                Arc::clone(&native),
                api_addr,
                std::time::SystemTime::now(),
                Instant::now(),
            )
            .await
            .unwrap(),
        );
        let server = crate::native_api::NativeServer::start(api_listener, state);
        let ingress = crate::control::udp_ingress::UdpLoopState::new(&plane, true);
        let tuples = crate::control::connection::build_tuples_key(
            destination.ip(),
            destination.port(),
            client_addr.ip(),
            client_addr.port(),
            17,
        );
        let mut backend = MockEbpfBackend::new();
        backend.publish_routing_plan(&plan, &[]).unwrap();
        backend.bind_kernel_trace_dictionary(
            crate::observe::flows::kernel::KernelTraceDictionary::prepare(
                &native.core.instance_id,
                17,
                &router,
                &config,
                &plan,
            )
            .unwrap(),
        );
        let descriptor = backend.routing_snapshot().descriptor;
        let mut witness = KernelRouteWitness {
            tuple: tuples,
            ..Default::default()
        };
        witness.output.flags = ROUTE_TRACE_VERSION | ROUTE_TRACE_ENABLED | ROUTE_TRACE_COMPLETE;
        witness.output.policy_id = descriptor.trace_policy;
        witness.output.generation = descriptor.generation;
        witness.output.decision = RoutingDecision {
            outbound: OutboundIndex::Direct as u32,
            domain_final: 1,
            ..Default::default()
        };
        witness.output.input.src_ip = *tuples.src_ip.as_bytes();
        witness.output.input.dst_ip = *tuples.dst_ip.as_bytes();
        witness.output.input.src_port = u32::from(tuples.src_port);
        witness.output.input.dst_port = u32::from(tuples.dst_port);
        witness.output.input.l4proto = 2;
        witness.output.input.dscp = 8;
        witness.output.outcomes[0] = ROUTE_TRACE_MATCHED;
        let first_id = backend.capture_route_witness(witness);
        let reference = crate::observe::flows::kernel::KernelRouteReference {
            trace_id: first_id,
            decision_token: 0,
            routing_generation: descriptor.generation,
            effective_outbound: OutboundIndex::Direct as u8,
            mark: Some(0),
            must: Some(0),
        };
        assert_eq!(
            backend
                .capture_kernel_route(
                    &tuples,
                    crate::observe::flows::kernel::KernelRouteReference {
                        effective_outbound: OutboundIndex::Block as u8,
                        ..reference
                    },
                )
                .unwrap_err(),
            "kernel_trace_action_mismatch"
        );
        let captured = backend.capture_kernel_route(&tuples, reference).unwrap();
        assert_eq!(captured.gap, None);
        assert_eq!(captured.rules[0].result, "matched");
        let config_guard = plane.config.write().await;
        ingress
            .dispatch_datagram_at(
                b"queued-original",
                client_addr,
                &crate::control::sockets::UdpRecvMeta {
                    original_dst_cmsg: Some(destination),
                    packet_dst_ip: Some(destination.ip()),
                    packet_ifindex: Some(1),
                    packet_mark: Some(TPROXY_MARK),
                    packet_priority: Some(first_id),
                    local_addr: make_addr("0.0.0.0", 15000),
                },
                crate::control::udp_endpoint::queue_now(),
            )
            .await;
        let current_id = if recreated {
            witness.output.input.dscp = 46;
            backend.capture_route_witness(witness)
        } else {
            first_id
        };
        backend
            .udp_conn_state_store(
                &tuples,
                &ConnState {
                    trace_id: current_id,
                    ..Default::default()
                },
            )
            .unwrap();
        backend.routing_handoffs.lock().insert(
            *backend.udp_conn_states.keys().next().unwrap(),
            RoutingHandoffEntry {
                trace_id: current_id,
                routing_generation: descriptor.generation,
                result: RoutingResult {
                    dscp: if recreated { 46 } else { 8 },
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        *plane.ebpf.write().await = Box::new(backend);
        drop(config_guard);
        let mut received = [0; 64];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut received))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&received[..length], b"queued-original");
        assert_eq!(
            upstream.try_recv_from(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let page: serde_json::Value = http
            .get(format!("http://{api_addr}/api/v1/flows"))
            .bearer_auth("udp-lineage-test")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(page["flows"].as_array().unwrap().len(), 1);
        let id = page["flows"][0]["id"].as_str().unwrap();
        let detail: serde_json::Value = http
            .get(format!("http://{api_addr}/api/v1/flows/{id}"))
            .bearer_auth("udp-lineage-test")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let steps = detail["trace"]["steps"].as_array().unwrap();
        let kernel_routes: Vec<_> = steps
            .iter()
            .filter(|step| step["stage"] == "route" && step["data"]["plane"] == "kernel")
            .collect();
        if recreated {
            assert!(
                kernel_routes.is_empty(),
                "queued A must not adopt the current B witness"
            );
            assert_eq!(detail["trace"]["status"], "partial");
        } else {
            assert_eq!(
                kernel_routes.len(),
                1,
                "an exact packet carrier retains kernel evidence"
            );
            assert_eq!(kernel_routes[0]["data"]["input"]["dscp"], 8);
            assert_eq!(kernel_routes[0]["data"]["rules"][0]["result"], "matched");
            assert_eq!(
                kernel_routes[0]["data"]["evaluation_id"],
                format!("{}:kernel:{first_id}", native.core.instance_id)
            );
        }
        assert!(plane.udp_pool.shutdown().await.joined);
        server.shutdown().await;
    }
}
