use super::*;
use crate::control::tests::{
    store_active_tcp_flow,
    support::{canonical_socks5, test_dns_forwarder},
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    plane: ControlPlane,
    handle: ControlPlaneHandle,
    server: crate::native_api::NativeServer,
    http: reqwest::Client,
    api: String,
    listener: tokio::net::TcpListener,
    client: TcpStream,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Fixture {
    async fn new(selected: &str, dial_mode: &str) -> anyhow::Result<Self> {
        Self::with_recording(selected, dial_mode, true).await
    }

    async fn with_recording(
        selected: &str,
        dial_mode: &str,
        recording: bool,
    ) -> anyhow::Result<Self> {
        Self::with_config(selected, dial_mode, recording, |_| {}).await
    }

    async fn with_config(
        selected: &str,
        dial_mode: &str,
        recording: bool,
        configure: impl FnOnce(&mut Config),
    ) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let destination = listener.local_addr()?;
        let client = TcpStream::connect(destination).await?;
        let (accepted, source) = listener.accept().await?;
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        config.nodes.push(canonical_socks5(
            "peer",
            "127.0.0.1",
            destination.port(),
            None,
        ));
        config.global.dial_mode = dial_mode.into();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.global.connect_timeout_ms = 5_000;
        config.routing.default_outbound = "outer".into();
        config.groups = vec![
            Group {
                name: "outer".into(),
                groups: vec!["inner".into()],
                ..Default::default()
            },
            Group {
                name: "inner".into(),
                nodes: config.nodes.iter().map(|node| node.id).collect(),
                default: Some(selected.into()),
                ..Default::default()
            },
        ];
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.record_flows = recording;
        config.experimental.native_api.allow_anonymous_loopback = true;
        configure(&mut config);
        let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
        let mut plane = ControlPlane::new(
            config,
            Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
            router,
            Arc::new(ProxyRegistry::default_resolver()?),
            DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
            test_dns_forwarder(),
        )?;
        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = api_listener.local_addr()?;
        let state = crate::native_api::NativeState::new(
            &mut plane,
            address,
            std::time::SystemTime::now(),
            std::time::Instant::now(),
        )
        .await?;
        let server = crate::native_api::NativeServer::start(api_listener, Arc::new(state));
        let http = reqwest::Client::builder().no_proxy().build()?;
        http.get(format!("http://{address}/api/v1/flows"))
            .send()
            .await?
            .error_for_status()?;
        let handle = plane.spawn_handle();
        handle.connection_tracker.disable_api();
        store_active_tcp_flow(&handle, destination, source).await?;
        let worker = handle.clone();
        let task = tokio::spawn(async move { worker.serve_connection(accepted, source).await });
        Ok(Self {
            plane,
            handle,
            server,
            http,
            api: format!("http://{address}/api/v1"),
            listener,
            client,
            task,
        })
    }

    async fn flow(&self, state: &str) -> anyhow::Result<Value> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let list: Value = self
                    .http
                    .get(format!("{}/flows", self.api))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                if let Some(row) = list["flows"].as_array().and_then(|rows| rows.first())
                    && row["state"] == state
                {
                    let id = row["id"].as_str().unwrap();
                    return self
                        .http
                        .get(format!("{}/flows/{id}", self.api))
                        .send()
                        .await?
                        .error_for_status()?
                        .json::<Value>()
                        .await
                        .map_err(anyhow::Error::from);
                }
                tokio::task::yield_now().await;
            }
        })
        .await?
    }
}

fn steps(flow: &Value, stage: &str) -> Vec<Value> {
    flow["trace"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["stage"] == stage)
        .cloned()
        .collect()
}

fn leaf_attempts(flow: &Value) -> Vec<Value> {
    steps(flow, "outbound")
        .into_iter()
        .filter(|step| step["data"]["kind"] == "leaf")
        .collect()
}

#[tokio::test]
async fn native_tcp_success_keeps_decision_path_after_selector_change() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = Fixture::new("peer", "ip").await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        let mut greeting = [0; 3];
        upstream.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 0]);
        upstream.write_all(&[5, 0]).await?;
        let mut connect = [0; 10];
        upstream.read_exact(&mut connect).await?;
        assert_eq!(&connect[..4], &[5, 1, 0, 1]);
        upstream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await?;
        let catalog = fixture.handle.native.as_ref().unwrap().catalog.snapshot();
        let leaf_id = fixture
            .handle
            .config
            .read()
            .await
            .nodes
            .iter()
            .find(|node| node.name == "peer")
            .unwrap()
            .id
            .to_string();
        fixture.client.write_all(b"request").await?;
        let mut request = [0; 7];
        upstream.read_exact(&mut request).await?;
        assert_eq!(&request, b"request");
        upstream.write_all(b"reply").await?;
        let mut reply = [0; 5];
        fixture.client.read_exact(&mut reply).await?;
        assert_eq!(&reply, b"reply");
        let before = fixture.flow("active").await?;
        assert_eq!(before["outbound"], "outer");
        let rule_id = format!("{}:0:fallback", before["instance_id"].as_str().unwrap());
        assert_eq!(before["rule_id"], rule_id);
        assert_eq!(before["rule_source"], "recomputed");
        let flows: Value = fixture
            .http
            .get(format!("{}/flows", fixture.api))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let summary = flows["flows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == before["id"])
            .unwrap();
        assert_eq!(summary["rule_id"], rule_id);
        assert_eq!(summary["rule_source"], "recomputed");
        assert_eq!(
            before["chain"],
            serde_json::json!([catalog.groups["outer"], catalog.groups["inner"], leaf_id])
        );
        let attempts = leaf_attempts(&before);
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0]["data"]["status"], "started");
        assert_eq!(attempts[1]["data"]["status"], "succeeded");
        assert_eq!(
            attempts[0]["data"]["attempt_id"],
            attempts[1]["data"]["attempt_id"]
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][0]["member_name"],
            "inner"
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][1]["member_name"],
            "peer"
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][0]["group_id"],
            catalog.groups["outer"]
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][0]["member_id"],
            catalog.groups["inner"]
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][1]["group_id"],
            catalog.groups["inner"]
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][1]["member_id"],
            leaf_id
        );
        let leaf_id = &attempts[0]["data"]["attempt_id"];
        let transports: Vec<_> = steps(&before, "outbound")
            .into_iter()
            .filter(|step| step["data"]["kind"] == "transport")
            .collect();
        assert_eq!(transports.len(), 2);
        assert_eq!(transports[0]["data"]["status"], "started");
        assert_eq!(transports[1]["data"]["status"], "succeeded");
        for transport in &transports {
            assert_eq!(&transport["data"]["parent_attempt_id"], leaf_id);
            assert_eq!(
                transport["data"]["server_addr"],
                fixture.listener.local_addr()?.to_string()
            );
            assert_eq!(transport["generation_id"], attempts[0]["generation_id"]);
        }
        let connection = steps(&before, "connection");
        for reason in ["routing_started", "tcp_dial_started"] {
            assert!(
                connection
                    .iter()
                    .any(|step| step["data"]["reason"] == reason)
            );
        }
        for reason in [
            "dial_succeeded",
            "application_send_accepted",
            "protocol_request_sent",
            "target_confirmed",
            "response_received",
        ] {
            let facts: Vec<_> = connection
                .iter()
                .filter(|step| step["data"]["reason"] == reason)
                .collect();
            assert_eq!(facts.len(), 1, "{reason} must have one source owner");
            assert_eq!(&facts[0]["data"]["attempt_id"], leaf_id);
        }
        let selection = connection
            .iter()
            .find(|step| step["data"]["reason"] == "selection_evaluated")
            .unwrap();
        assert!(
            selection["data"]["selections"]
                .as_array()
                .unwrap()
                .iter()
                .any(|decision| {
                    decision["group_id"] == catalog.groups["inner"]
                        && decision["member_name"] == "peer"
                        && decision["selection"]["candidates"].as_array().is_some_and(
                            |candidates| {
                                candidates.iter().any(|candidate| {
                                    candidate["member_name"] == "peer"
                                        && candidate["selected"] == true
                                })
                            },
                        )
                })
        );
        assert_eq!(
            steps(&before, "connection")
                .iter()
                .filter(|step| step["data"]["milestone"] == "first_reply")
                .count(),
            1
        );
        fixture
            .handle
            .group_manager
            .read()
            .set_selector_choice(
                "inner",
                "block",
                honk_outbound::group::SelectorNetworks::Both,
            )
            .unwrap();
        let after = fixture.flow("active").await?;
        assert_eq!(leaf_attempts(&after), attempts);
        assert_eq!(after["chain"], before["chain"]);
        let connections: Value = fixture
            .http
            .get(format!("{}/connections", fixture.api))
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(connections["tcp"][0]["flow_id"], before["id"]);
        assert_eq!(connections["tcp"][0]["rule_id"], rule_id);
        assert_eq!(connections["tcp"][0]["rule_source"], "recomputed");
        fixture.client.shutdown().await?;
        upstream.shutdown().await?;
        (&mut fixture.task).await??;
        let closed = fixture.flow("closed").await?;
        assert_eq!(closed["id"], before["id"]);
        assert_eq!(
            steps(&closed, "connection")
                .iter()
                .filter(|step| step["data"]["milestone"] == "terminal")
                .count(),
            1
        );
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_lost_leaf_capture_does_not_invent_physical_routing_provenance()
-> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = Fixture::with_config("peer", "ip", true, |config| {
            for index in 0..200 {
                let node = canonical_socks5(
                    &format!("candidate-{index}-{}", "n".repeat(200)),
                    "127.0.0.1",
                    10_000 + index,
                    None,
                );
                config.nodes.push(node);
            }
            let outer = &mut config.groups[0];
            outer.policy = honk_config::node::GroupPolicy::URLTest;
            outer.groups.clear();
            outer.nodes = config
                .nodes
                .iter()
                .filter(|node| node.protocol() == honk_config::types::NodeProtocol::Socks5)
                .map(|node| node.id)
                .collect();
        })
        .await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        let mut greeting = [0; 3];
        upstream.read_exact(&mut greeting).await?;
        upstream.write_all(&[5, 0]).await?;
        let mut request = [0; 10];
        upstream.read_exact(&mut request).await?;
        upstream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await?;
        fixture.client.write_all(b"x").await?;
        let mut payload = [0; 1];
        upstream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"x");
        let flow = fixture.flow("active").await?;
        assert!(leaf_attempts(&flow).is_empty());
        let physical = steps(&flow, "outbound")
            .into_iter()
            .find(|step| {
                step["data"]["kind"] == "transport" && step["data"]["status"] == "succeeded"
            })
            .unwrap();
        assert!(physical["data"]["parent_attempt_id"].is_string());
        assert_eq!(physical["data"]["routing_source"], "unknown");
        assert_eq!(physical["data"]["x-honk"]["mode_override"], "unknown");
        assert_eq!(flow["trace"]["status"], "partial");
        assert!(
            flow["trace"]["missing"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("buffer_overflow"))
        );
        fixture.client.shutdown().await?;
        upstream.shutdown().await?;
        (&mut fixture.task).await??;
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_proxy_hostname_resolution_is_not_business_target_resolution()
-> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = Fixture::with_config("peer", "ip", true, |config| {
            let peer = config
                .nodes
                .iter_mut()
                .find(|node| node.name == "peer")
                .unwrap();
            let old = peer.id;
            *peer = canonical_socks5("peer", "localhost", peer.port, None);
            let replacement = peer.id;
            for group in &mut config.groups {
                for member in &mut group.nodes {
                    if *member == old {
                        *member = replacement;
                    }
                }
            }
        })
        .await?;
        let (mut proxy, _) = fixture.listener.accept().await?;
        let mut greeting = [0; 3];
        proxy.read_exact(&mut greeting).await?;
        proxy.write_all(&[5, 0]).await?;
        let mut request = [0; 10];
        proxy.read_exact(&mut request).await?;
        proxy.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
        let flow = fixture.flow("active").await?;
        let lookups = steps(&flow, "dns");
        let resolution = lookups
            .iter()
            .find(|step| {
                step["data"]["name"] == "localhost" && step["data"]["status"] == "succeeded"
            })
            .expect("the actual proxy hostname resolution is recorded");
        assert_eq!(resolution["data"]["purpose"], "proxy_server");
        assert_eq!(resolution["data"]["source"], "hosts");
        assert_eq!(resolution["data"]["cache"], "bypass");
        assert!(resolution["data"]["upstream"].is_null());
        assert!(
            lookups
                .iter()
                .filter(|step| step["data"]["name"] == "localhost")
                .all(|step| step["data"]["source"] != "unknown")
        );
        assert!(
            lookups
                .iter()
                .filter(|step| step["data"]["name"] == "localhost")
                .all(|step| step["data"]["purpose"] == "proxy_server")
        );
        fixture.client.shutdown().await?;
        proxy.shutdown().await?;
        (&mut fixture.task).await??;
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_retains_block_and_failed_dial_without_connection() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        for selected in ["block", "peer"] {
            let mut fixture = Fixture::new(selected, "ip").await?;
            if selected == "peer" {
                let (upstream, _) = fixture.listener.accept().await?;
                drop(upstream);
            }
            let state = if selected == "block" {
                "blocked"
            } else {
                "failed"
            };
            let flow = fixture.flow(state).await?;
            assert!(flow["connection_id"].is_null());
            assert!(flow["ended_at"].is_string());
            let attempts = leaf_attempts(&flow);
            assert_eq!(attempts.len(), 2);
            assert_eq!(attempts[0]["data"]["status"], "started");
            assert_eq!(attempts[1]["data"]["status"], "failed");
            assert_eq!(attempts[1]["data"]["leaf_node_name"], selected);
            assert_eq!(
                attempts[0]["data"]["attempt_id"],
                attempts[1]["data"]["attempt_id"]
            );
            assert!(!steps(&flow, "connection").iter().any(|step| matches!(
                step["data"]["milestone"].as_str(),
                Some("target_confirmed" | "first_reply")
            ) || step["data"]["reason"]
                == "application_send_accepted"));
            if selected == "block" {
                assert!(
                    !steps(&flow, "outbound")
                        .iter()
                        .any(|step| step["data"]["kind"] == "transport")
                );
            }
            (&mut fixture.task).await??;
            assert_eq!(
                fixture.handle.stats.snapshot()["outer"].errors,
                u32::from(selected == "peer")
            );
            assert_eq!(fixture.handle.stats.snapshot()["outer"].active_conns, 0);
            fixture.server.shutdown().await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_cancelled_attempt_keeps_pre_reload_generation_and_name() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = Fixture::new("peer", "ip").await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        let mut greeting = [0; 3];
        upstream.read_exact(&mut greeting).await?;
        assert_eq!(greeting[0], 5);
        let before = fixture.flow("dialing").await?;
        let attempt = leaf_attempts(&before).pop().unwrap();
        assert_eq!(attempt["data"]["status"], "started");
        let mut replacement = fixture.handle.config.read().await.as_ref().clone();
        replacement
            .nodes
            .iter_mut()
            .find(|node| node.name == "peer")
            .unwrap()
            .name = "renamed".into();
        replacement
            .groups
            .iter_mut()
            .find(|group| group.name == "inner")
            .unwrap()
            .default = Some("renamed".into());
        assert!(
            fixture
                .plane
                .reload_runtime_config(replacement, Default::default())
                .await
        );
        fixture.task.abort();
        assert!((&mut fixture.task).await.unwrap_err().is_cancelled());
        assert_eq!(fixture.handle.stats.snapshot()["outer"].active_conns, 0);
        let cancelled = fixture.flow("failed").await?;
        let attempts = leaf_attempts(&cancelled);
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[1]["data"]["status"], "cancelled");
        assert_eq!(attempts[1]["generation_id"], attempt["generation_id"]);
        assert_eq!(attempts[1]["data"]["leaf_node_name"], "peer");
        assert_eq!(
            attempts[1]["data"]["selection_path"],
            attempt["data"]["selection_path"]
        );
        assert_eq!(
            attempts[1]["data"]["attempt_id"],
            attempt["data"]["attempt_id"]
        );
        let physical = steps(&cancelled, "outbound");
        let started = physical
            .iter()
            .find(|step| step["data"]["kind"] == "transport" && step["data"]["status"] == "started")
            .unwrap();
        assert_eq!(started["generation_id"], attempt["generation_id"]);
        assert_eq!(
            started["data"]["parent_attempt_id"],
            attempt["data"]["attempt_id"]
        );
        assert!(
            !steps(&cancelled, "connection")
                .iter()
                .any(|step| step["data"]["milestone"] == "target_confirmed")
        );
        assert_eq!(
            steps(&cancelled, "connection")
                .iter()
                .filter(|step| step["data"]["milestone"] == "terminal")
                .count(),
            1
        );
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_http_host_does_not_replace_consumed_ip_routing_input() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = Fixture::new("direct", "domain+").await?;
        let request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        fixture.client.write_all(request).await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        let mut received = vec![0; request.len()];
        upstream.read_exact(&mut received).await?;
        assert_eq!(received, request);
        let flow = fixture.flow("active").await?;
        assert_eq!(flow["input"]["domain"], "example.test");
        assert_eq!(flow["domain_source"], "http_host");
        assert_eq!(flow["chain"], serde_json::json!([]));
        let route = steps(&flow, "route").pop().unwrap();
        assert_eq!(route["data"]["plane"], "userspace");
        assert!(route["data"]["input"]["domain"].is_null());
        let dial_mode = steps(&flow, "dial_mode").pop().unwrap();
        assert_eq!(dial_mode["data"]["configured"], "domain+");
        assert_eq!(dial_mode["data"]["verification"], "not_required");
        assert_eq!(dial_mode["data"]["effective_target"], "ip");
        let accepted: Vec<_> = steps(&flow, "connection")
            .into_iter()
            .filter(|step| step["data"]["reason"] == "application_send_accepted")
            .collect();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0]["data"]["milestone"], "unknown");
        assert_eq!(
            accepted[0]["data"]["attempt_id"],
            leaf_attempts(&flow)[0]["data"]["attempt_id"]
        );
        fixture.client.shutdown().await?;
        upstream.shutdown().await?;
        (&mut fixture.task).await??;
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_delete_closes_both_peers_without_recording() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = Fixture::with_recording("direct", "ip", false).await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        fixture.client.write_all(b"live").await?;
        let mut bytes = [0; 4];
        upstream.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"live");
        let tracker = &fixture.handle.connection_tracker;
        let catalog = fixture.handle.native.as_ref().unwrap().catalog.snapshot();
        assert_eq!(
            tracker
                .snapshot_group(&catalog.groups["outer"], Some("tcp"))
                .len(),
            1
        );
        assert!(
            tracker
                .snapshot_group(&catalog.groups["inner"], Some("udp"))
                .is_empty()
        );
        fixture
            .handle
            .group_manager
            .read()
            .set_selector_choice(
                "inner",
                "block",
                honk_outbound::group::SelectorNetworks::Both,
            )
            .unwrap();
        let connection = tracker.snapshot().pop().unwrap();
        assert_eq!(
            tracker
                .snapshot_group(&catalog.groups["inner"], Some("tcp"))
                .len(),
            1
        );
        let path = format!("{}/connections/{}", fixture.api, connection.id);
        let response = fixture
            .http
            .delete(&path)
            .header("idempotency-key", "close-once")
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
        assert_eq!(fixture.client.read(&mut bytes).await?, 0);
        assert_eq!(upstream.read(&mut bytes).await?, 0);
        (&mut fixture.task).await??;
        assert!(tracker.snapshot().is_empty());
        assert_eq!(fixture.handle.stats.snapshot()["outer"].tx_bytes, 4);
        let again = fixture
            .http
            .delete(&path)
            .header("idempotency-key", "close-once")
            .send()
            .await?;
        assert_eq!(again.status(), reqwest::StatusCode::NOT_FOUND);
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn tcp_close_claims_share_guard_retirement() -> anyhow::Result<()> {
    use crate::connection_tracker::CloseOutcome;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = Fixture::with_recording("direct", "ip", false).await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        fixture.client.write_all(b"x").await?;
        let mut byte = [0];
        upstream.read_exact(&mut byte).await?;
        let tracker = &fixture.handle.connection_tracker;
        let connection = tracker.snapshot().pop().unwrap();
        let backend = fixture.handle.ebpf.write().await;
        let selected = tracker
            .snapshot_close(Some("tcp"), None, 1000)
            .unwrap()
            .pop()
            .unwrap();
        let disappeared = tracker
            .snapshot_close(Some("tcp"), None, 1000)
            .unwrap()
            .pop()
            .unwrap();
        let completion = tracker.start_close(selected);
        let mut duplicate = Box::pin(tracker.close_id(&connection.id));
        assert!(futures::poll!(&mut duplicate).is_pending());
        assert_eq!(upstream.read(&mut byte).await?, 0);
        let mut completion = Box::pin(completion.wait());
        assert!(futures::poll!(&mut completion).is_pending());
        assert_eq!(tracker.snapshot().len(), 1);
        drop(backend);
        assert_eq!(completion.await, CloseOutcome::Closed);
        assert_eq!(duplicate.await, CloseOutcome::Closed);
        assert_eq!(fixture.client.read(&mut byte).await?, 0);
        (&mut fixture.task).await??;
        assert_eq!(
            tracker.close_selected(disappeared).await,
            CloseOutcome::Gone
        );
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_bulk_oversize_counts_unowned_mapped_sources_before_any_close() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = Fixture::with_recording("direct", "ip", false).await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        fixture.client.write_all(b"x").await?;
        let mut byte = [0];
        upstream.read_exact(&mut byte).await?;
        let tracker = &fixture.handle.connection_tracker;
        for index in 0..1000 {
            tracker.register(crate::connection_tracker::ConnectionEntry {
                id: format!("observed-{index}"),
                source: format!("[::ffff:127.0.0.1]:{}", index + 1),
                destination: "192.0.2.1:443".into(),
                proxy: "direct".into(),
                routed_outbound: None,
                native_flow_id: None,
                rule: String::new(),
                rule_payload: String::new(),
                chains: Vec::new(),
                upload: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                download: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                start_time: std::time::Instant::now(),
                domain: None,
                network: "tcp".into(),
                process: None,
                process_path: None,
            });
        }
        let base = format!("{}/connections", fixture.api);
        let unfiltered = fixture
            .http
            .delete(format!("{base}?type=all"))
            .send()
            .await?;
        assert_eq!(unfiltered.status(), reqwest::StatusCode::BAD_REQUEST);
        let oversized = fixture
            .http
            .delete(format!("{base}?type=tcp&src=127.0.0.1"))
            .send()
            .await?;
        assert_eq!(oversized.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
        fixture.client.write_all(b"y").await?;
        upstream.read_exact(&mut byte).await?;
        assert_eq!(&byte, b"y");
        let unowned = fixture
            .http
            .delete(format!("{base}/observed-0"))
            .send()
            .await?;
        assert_eq!(unowned.status(), reqwest::StatusCode::CONFLICT);
        for index in 0..1000 {
            tracker.remove(&format!("observed-{index}"));
        }
        let closed: Value = fixture
            .http
            .delete(format!("{base}?type=tcp&src=::ffff:127.0.0.1"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(closed, serde_json::json!({"closed":1,"skipped":0}));
        assert_eq!(fixture.client.read(&mut byte).await?, 0);
        assert_eq!(upstream.read(&mut byte).await?, 0);
        (&mut fixture.task).await??;
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn aborted_tcp_close_does_not_acknowledge_guard_retirement() -> anyhow::Result<()> {
    use crate::connection_tracker::CloseOutcome;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = Fixture::new("direct", "ip").await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        fixture.client.write_all(b"x").await?;
        let mut byte = [0];
        upstream.read_exact(&mut byte).await?;
        let tracker = &fixture.handle.connection_tracker;
        let backend = fixture.handle.ebpf.write().await;
        let selected = tracker
            .snapshot_close(Some("tcp"), None, 1000)
            .unwrap()
            .pop()
            .unwrap();
        let completion = tracker.start_close(selected);
        let mut duplicate = Box::pin(
            tracker.close_selected(
                tracker
                    .snapshot_close(Some("tcp"), None, 1000)
                    .unwrap()
                    .pop()
                    .unwrap(),
            ),
        );
        assert!(futures::poll!(&mut duplicate).is_pending());
        assert_eq!(upstream.read(&mut byte).await?, 0);
        let retiring = fixture.flow("active").await?;
        assert!(retiring["ended_at"].is_null());
        assert!(
            !steps(&retiring, "connection")
                .iter()
                .any(|step| step["data"]["milestone"] == "terminal")
        );
        fixture.task.abort();
        assert!((&mut fixture.task).await.unwrap_err().is_cancelled());
        assert_eq!(completion.wait().await, CloseOutcome::Failed);
        assert_eq!(duplicate.await, CloseOutcome::Failed);
        assert_eq!(fixture.client.read(&mut byte).await?, 0);
        drop(backend);
        let cancelled = fixture.flow("failed").await?;
        let terminals: Vec<_> = steps(&cancelled, "connection")
            .into_iter()
            .filter(|step| step["data"]["milestone"] == "terminal")
            .collect();
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0]["data"]["reason"], "cancelled");
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_race_links_only_actual_winner_and_cancels_loser() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let backup = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let backup_addr = backup.local_addr()?;
        let mut fixture = Fixture::with_config("peer", "ip", true, |config| {
            config.nodes.push(canonical_socks5(
                "winner",
                "127.0.0.1",
                backup_addr.port(),
                None,
            ));
            let outer = &mut config.groups[0];
            outer.policy = honk_config::node::GroupPolicy::URLTest;
            outer.groups.clear();
            outer.nodes = config
                .nodes
                .iter()
                .filter(|node| node.protocol() == honk_config::types::NodeProtocol::Socks5)
                .map(|node| node.id)
                .collect();
        })
        .await?;
        let (mut loser, _) = fixture.listener.accept().await?;
        let mut greeting = [0; 3];
        loser.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 0]);
        let (mut winner, _) = backup.accept().await?;
        winner.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 0]);
        let pending = fixture.flow("dialing").await?;
        assert!(
            !steps(&pending, "connection")
                .iter()
                .any(|step| step["data"]["milestone"] == "target_confirmed")
        );
        winner.write_all(&[5, 0]).await?;
        let mut connect = [0; 10];
        winner.read_exact(&mut connect).await?;
        winner.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
        fixture.client.write_all(b"request").await?;
        let mut request = [0; 7];
        winner.read_exact(&mut request).await?;
        assert_eq!(&request, b"request");
        winner.write_all(b"reply").await?;
        let mut reply = [0; 5];
        fixture.client.read_exact(&mut reply).await?;
        assert_eq!(&reply, b"reply");
        assert_eq!(loser.read(&mut greeting).await?, 0);
        fixture.client.shutdown().await?;
        winner.shutdown().await?;
        (&mut fixture.task).await??;
        let closed = fixture.flow("closed").await?;
        let attempts = leaf_attempts(&closed);
        let succeeded = attempts
            .iter()
            .find(|step| step["data"]["status"] == "succeeded")
            .unwrap();
        let cancelled = attempts
            .iter()
            .find(|step| step["data"]["status"] == "cancelled")
            .unwrap();
        assert_eq!(attempts.len(), 4);
        assert_eq!(succeeded["data"]["leaf_node_name"], "winner");
        assert_eq!(cancelled["data"]["leaf_node_name"], "peer");
        assert_ne!(
            succeeded["data"]["attempt_id"],
            cancelled["data"]["attempt_id"]
        );
        let connection = steps(&closed, "connection");
        for reason in [
            "dial_succeeded",
            "application_send_accepted",
            "response_received",
            "relay_closed",
        ] {
            let fact = connection
                .iter()
                .find(|step| step["data"]["reason"] == reason)
                .unwrap();
            assert_eq!(fact["data"]["attempt_id"], succeeded["data"]["attempt_id"]);
        }
        let confirmed: Vec<_> = connection
            .iter()
            .filter(|step| step["data"]["milestone"] == "target_confirmed")
            .collect();
        assert_eq!(confirmed.len(), 1);
        assert_eq!(
            confirmed[0]["data"]["attempt_id"],
            succeeded["data"]["attempt_id"]
        );
        let physical: Vec<_> = steps(&closed, "outbound")
            .into_iter()
            .filter(|step| {
                step["data"]["kind"] == "transport" && step["data"]["status"] == "started"
            })
            .collect();
        assert_eq!(physical.len(), 2);
        for attempt in [succeeded, cancelled] {
            assert!(
                physical
                    .iter()
                    .any(|transport| transport["data"]["parent_attempt_id"]
                        == attempt["data"]["attempt_id"])
            );
        }
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_empty_plan_records_selection_without_dial() -> anyhow::Result<()> {
    let mut fixture = Fixture::with_config("peer", "ip", true, |config| {
        config.groups[1].nodes.clear();
        config.groups[1].default = None;
    })
    .await?;
    (&mut fixture.task).await??;
    let failed = fixture.flow("failed").await?;
    assert!(steps(&failed, "outbound").is_empty());
    let connection = steps(&failed, "connection");
    assert!(
        connection
            .iter()
            .any(|step| step["data"]["reason"] == "selection_evaluated")
    );
    let terminal = connection
        .iter()
        .find(|step| step["data"]["milestone"] == "terminal")
        .unwrap();
    assert_eq!(terminal["data"]["reason"], "no_available_nodes");
    let dial = steps(&failed, "dial_mode").pop().unwrap();
    assert_eq!(dial["data"]["effective_target"], "none");
    assert_eq!(dial["data"]["reason"], "no_eligible_candidates");
    fixture.server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn native_tcp_overall_deadline_retains_cancelled_started_attempt() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = Fixture::new("block", "ip").await?;
        (&mut fixture.task).await??;
        let config = fixture.handle.config.read().await.clone();
        let native = fixture.handle.native.as_ref().unwrap();
        let node = config
            .nodes
            .iter()
            .find(|node| node.name == "peer")
            .unwrap();
        let target = fixture.listener.local_addr()?;
        let mut observation = ConnectionObservation::begin(
            Some(native),
            crate::observe::vocab::Network::Tcp,
            fixture.client.local_addr()?,
            target,
        );
        observation.pin_selection(
            fixture.handle.diagnostics.read().generation,
            &native.catalog.snapshot(),
            &config,
        );
        let generation = fixture.handle.runtime_registry.read().clone();
        let candidates = [node];
        let feedback = HashMap::new();
        let chains = HashMap::new();
        let race = fixture.handle.race_candidates(
            &candidates,
            target,
            None,
            "outer",
            crate::stats::OutboundKind::Group,
            None,
            Duration::from_secs(5),
            tokio::time::Instant::now() + Duration::from_millis(100),
            generation,
            IpVersion::V4,
            &feedback,
            false,
            &chains,
            &observation,
        );
        let (result, peer) = tokio::join!(race, async {
            let (mut peer, _) = fixture.listener.accept().await?;
            let mut greeting = [0; 3];
            peer.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 1, 0]);
            Ok::<_, anyhow::Error>(peer)
        });
        assert!(result?.is_none());
        let mut peer = peer?;
        assert_eq!(peer.read(&mut [0]).await?, 0);
        let flow = fixture.flow("observed").await?;
        let attempts = leaf_attempts(&flow);
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0]["data"]["status"], "started");
        assert_eq!(attempts[1]["data"]["status"], "cancelled");
        assert_eq!(
            attempts[0]["data"]["attempt_id"],
            attempts[1]["data"]["attempt_id"]
        );
        let connection = steps(&flow, "connection");
        let deadline = connection
            .iter()
            .find(|step| step["data"]["reason"] == "dial_deadline_exceeded")
            .unwrap();
        assert_eq!(deadline["data"]["error"], "dial_timeout");
        assert!(flow["ended_at"].is_null());
        assert!(!connection.iter().any(|step| matches!(
            step["data"]["milestone"].as_str(),
            Some("target_confirmed" | "first_reply")
        )));
        observation.finish(
            crate::observe::vocab::ConnectionState::Failed,
            "dial_failed",
        );
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
