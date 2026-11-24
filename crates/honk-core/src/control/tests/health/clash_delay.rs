use super::{canonical_socks5, control_plane};
use crate::clash_api::{self, ClashState};
use crate::control::ControlPlane;
use crate::control::tests::support::changed_routing_config;
use crate::ebpf::RoutingPushPhase;
use crate::mode::ModeState;
use crate::test_support::{Socks5Relay, socks5_chain, socks5_relay};
use honk_config::{
    Config,
    group::GroupPolicy,
    node::{Group, Node},
};
use honk_outbound::alive::{IpVersion, ProbeDomain};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Legacy delay sends the URL host using SOCKS5's domain address form,
/// including for a literal IPv4 URL.
async fn socks5_http_exit() -> Socks5Relay {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests: Arc<parking_lot::Mutex<Vec<SocketAddr>>> = Arc::default();
    let log = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut greeting = [0; 3];
                client.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                client.write_all(&[5, 0]).await.unwrap();
                let mut connect = [0; 14];
                client.read_exact(&mut connect).await.unwrap();
                assert_eq!(&connect, b"\x05\x01\x00\x03\x09127.0.0.1");
                let port = client.read_u16().await.unwrap();
                let target = SocketAddr::from(([127, 0, 0, 1], port));
                log.lock().push(target);
                let mut upstream = TcpStream::connect(target).await.unwrap();
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    Socks5Relay { addr, requests }
}

fn chain_config(front: &Socks5Relay, exit: &Socks5Relay) -> (Config, Uuid) {
    let nodes = socks5_chain(front, exit);
    let id = nodes[0].id;
    let mut config = Config {
        nodes: Vec::from(nodes),
        groups: vec![Group {
            name: "pool".into(),
            nodes: vec![id],
            ..Default::default()
        }],
        ..Default::default()
    };
    config.global.nfqueue_enable = false;
    (config, id)
}

struct ClashDelay {
    api: SocketAddr,
    client: Client,
    exit: Option<Socks5Relay>,
    path: &'static str,
    result_name: &'static str,
}

impl ClashDelay {
    fn new(
        api: SocketAddr,
        exit: Option<Socks5Relay>,
        path: &'static str,
        result_name: &'static str,
    ) -> Self {
        Self {
            api,
            client: Client::builder().no_proxy().build().unwrap(),
            exit,
            path,
            result_name,
        }
    }

    fn measure<T>(
        &self,
        status: &str,
        while_pending: impl Future<Output = T>,
    ) -> impl Future<Output = ((StatusCode, Value), T)> {
        self.measure_with_reply(Some(status), while_pending)
    }

    async fn measure_with_reply<T>(
        &self,
        status: Option<&str>,
        while_pending: impl Future<Output = T>,
    ) -> ((StatusCode, Value), T) {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap();
        let probe = async {
            let response = self
                .client
                .get(format!(
                    "http://{}{}?url=http://{addr}/probe&timeout=8000",
                    self.api, self.path
                ))
                .send()
                .await
                .unwrap();
            (response.status(), response.json().await.unwrap())
        };
        let peer = async {
            let (stream, _) = target.accept().await.unwrap();
            if let Some(exit) = &self.exit {
                assert!(exit.requests.lock().contains(&addr));
            }
            let mut peer = BufReader::new(stream);
            read_head(&mut peer).await;
            peer.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            read_head(&mut peer).await;
            let result = while_pending.await;
            if let Some(status) = status {
                let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
                peer.write_all(response.as_bytes()).await.unwrap();
            }
            result
        };
        tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(probe, peer) })
            .await
            .expect("delay did not complete both HTTP rounds")
    }

    fn success(&self, (status, body): (StatusCode, Value)) -> u64 {
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_object().unwrap().len(), 1);
        let delay = body[self.result_name].as_u64().expect("integer delay");
        assert!(delay <= u64::from(u16::MAX));
        delay
    }

    async fn document(&self, path: &str) -> Value {
        self.client
            .get(format!("http://{}{path}", self.api))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn visible_delay(&self, name: &str) -> Option<u64> {
        self.document(&format!("/proxies/{name}")).await["history"]
            .as_array()
            .unwrap()
            .first()
            .map(|entry| entry["delay"].as_u64().unwrap())
    }
}

async fn read_head(peer: &mut BufReader<TcpStream>) {
    let mut line = String::new();
    peer.read_line(&mut line).await.unwrap();
    assert_eq!(line, "HEAD /probe HTTP/1.1\r\n");
    loop {
        line.clear();
        assert_ne!(peer.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            break;
        }
    }
}

#[tokio::test]
async fn clash_node_delay_is_registration_scoped() {
    delay_is_registration_scoped("/proxies/via/delay", "delay").await;
}

#[tokio::test]
async fn clash_group_delay_is_registration_scoped() {
    delay_is_registration_scoped("/group/pool/delay", "via").await;
}

async fn spawn_clash(config: Config) -> (Arc<ControlPlane>, SocketAddr, JoinHandle<()>) {
    let mut control = control_plane(config);
    let mode_state = Arc::new(parking_lot::RwLock::new(ModeState::new("Rule", "pool")));
    control.set_mode_state(Arc::clone(&mode_state));
    control.start_datapath_flags_coordinator().unwrap();
    control
        .initialize_datapath_flags(false, false)
        .await
        .unwrap();
    let control = Arc::new(control);
    let state = Arc::new(ClashState {
        config: control.config_handle(),
        diagnostics: control.diagnostics_handle(),
        stats: control.stats_handle(),
        alive_set: control.alive_set(),
        group_manager: control.group_manager(),
        cache_db: None,
        connection_tracker: control.connection_tracker(),
        proxy_registry: control.proxy_registry(),
        runtime_registry: control.runtime_registry(),
        mode_state,
        datapath_flags: control.datapath_flags_handle().unwrap(),
        control: None,
        ui_download: control.ui_download_handle(),
        secret: String::new(),
        connection_pool: control.connection_pool(),
        external_ui: String::new(),
        router: control.traffic_router(),
        log_handle: clash_api::logs::layer::<tracing_subscriber::Registry>().1,
        dns_service: control.dns_service(),
        stream_samplers: Arc::new(clash_api::StreamSamplers::new()),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, clash_api::router(state))
            .await
            .unwrap();
    });
    (control, api, server)
}

async fn reload(control: &ControlPlane, config: Config) {
    assert!(
        control
            .reload_runtime_config(config, Default::default())
            .await
    );
}

/// The caller owns the warm coordinator mutex, so publication is observable
/// before warm work and URLTest idle/target resynchronization finish.
async fn publish_while_warm_blocked(
    control: &Arc<ControlPlane>,
    config: Config,
    after_publication: impl FnOnce(),
) -> JoinHandle<bool> {
    let generation = control.runtime_registry.read().generation();
    let plane = Arc::clone(control);
    let reload = tokio::spawn(async move {
        plane
            .reload_runtime_config(config, Default::default())
            .await
    });
    while control.runtime_registry.read().generation() == generation {
        assert!(!reload.is_finished(), "reload ended before publication");
        tokio::task::yield_now().await;
    }
    after_publication();
    reload
}

async fn delay_is_registration_scoped(path: &'static str, result_name: &'static str) {
    let front = socks5_relay().await;
    let exit = socks5_http_exit().await;
    let replacement = socks5_http_exit().await;
    let (config_a, a) = chain_config(&front, &exit);
    let (config_b, b) = chain_config(&front, &replacement);
    assert_ne!(a, b);

    let (control, api, server) = spawn_clash(config_a.clone()).await;
    let mut delay = ClashDelay::new(api, Some(exit), path, result_name);
    let alive = control.alive_set();
    let history = |id| alive.get_probe_history(id, ProbeDomain::Tcp, IpVersion::V4);
    let successes = |id| {
        history(id)
            .into_iter()
            .map(|sample| sample.success)
            .collect::<Vec<_>>()
    };
    let last = |id| alive.get_last_real_sample(id, ProbeDomain::Tcp, IpVersion::V4);
    let is_alive = || alive.is_alive_for(a, ProbeDomain::Tcp, IpVersion::V4);
    let force_dead = || alive.report_unavailable_forced(a, ProbeDomain::Tcp, IpVersion::V4);

    let prior = control.runtime_registry.read().clone();
    let mut unrelated = config_a.clone();
    unrelated.nodes.push(Config::builtin_block_node());
    let (response, ()) = delay
        .measure("204 No Content", async {
            reload(&control, unrelated).await;
            let successor = control.runtime_registry.read();
            assert!(!Arc::ptr_eq(
                &prior.get(&a).unwrap(),
                &successor.get(&a).unwrap()
            ));
            for hop in &config_a.nodes[1..] {
                assert!(Arc::ptr_eq(
                    &prior.get(&hop.id).unwrap(),
                    &successor.get(&hop.id).unwrap()
                ));
            }
        })
        .await;
    let measured = delay.success(response);
    assert_eq!(successes(a), [true]);
    assert_eq!(delay.visible_delay("via").await, Some(measured));

    // A metadata change can replace the exit runtime while preserving all node IDs.
    let mut replaced_exit = config_a.clone();
    replaced_exit.nodes[2].tags.push("new-exit-owner".into());
    let (response, ()) = delay
        .measure("204 No Content", async {
            reload(&control, replaced_exit).await;
            let successor = control.runtime_registry.read();
            let exit = config_a.nodes[2].id;
            assert!(!Arc::ptr_eq(
                &prior.get(&exit).unwrap(),
                &successor.get(&exit).unwrap()
            ));
        })
        .await;
    delay.success(response);
    assert_eq!(
        successes(a),
        [true],
        "replaced physical exit received a delay"
    );

    let (response, ()) = delay
        .measure("204 No Content", async {
            assert!(
                control
                    .reload_runtime_config(config_b.clone(), Default::default())
                    .await
            );
        })
        .await;
    delay.success(response);
    assert!(!alive.registered_nodes().contains_key(&a));
    assert!(
        history(a).is_empty() && last(a).is_none(),
        "removed A was recreated"
    );
    assert!(
        history(b).is_empty() && last(b).is_none(),
        "B inherited A's delay"
    );
    assert_eq!(delay.visible_delay("via").await, None);

    assert!(
        control
            .reload_runtime_config(config_a.clone(), Default::default())
            .await
    );

    // Isolate registration replacement from the runtime publication fence.
    let (response, ()) = delay
        .measure("204 No Content", async {
            let registration = alive.registered_nodes()[&a].clone();
            alive.remove_node(a);
            alive.register_node(a, registration.name, registration.raw_probe_address);
            force_dead();
        })
        .await;
    delay.success(response);
    assert_eq!(
        successes(a),
        [false],
        "an old registration credited its replacement"
    );

    let (response, ()) = delay
        .measure("204 No Content", async {
            assert!(
                control
                    .reload_runtime_config(config_b.clone(), Default::default())
                    .await
            );
            assert!(
                control
                    .reload_runtime_config(config_a, Default::default())
                    .await
            );
            force_dead();
        })
        .await;
    delay.success(response);
    assert!(!is_alive());
    assert_eq!(
        successes(a),
        [false],
        "A's old result reached reintroduced A"
    );

    let (failed, ()) = delay.measure("500 Internal Server Error", async {}).await;
    if result_name == "delay" {
        assert_eq!(failed.0, StatusCode::SERVICE_UNAVAILABLE);
    } else {
        assert_eq!(failed, (StatusCode::OK, json!({})));
    }
    assert_eq!(successes(a), [false]);
    assert_eq!(delay.visible_delay("via").await, None);

    let (first, ()) = delay.measure("204 No Content", async {}).await;
    delay.success(first);
    assert!(!is_alive(), "a stale result must not count toward recovery");
    let (second, ()) = delay.measure("204 No Content", async {}).await;
    let measured = delay.success(second);
    assert!(is_alive());
    assert_eq!(successes(a), [false, true, true]);
    assert_eq!(last(a).unwrap().0.as_millis(), u128::from(measured));
    assert!(
        alive
            .get_moving_average(a, ProbeDomain::Tcp, IpVersion::V4)
            .is_some()
    );
    assert!(
        alive
            .get_probe_history(a, ProbeDomain::Tcp, IpVersion::V6)
            .is_empty()
    );
    assert_eq!(delay.visible_delay("via").await, Some(measured));

    // Registrations must already agree with the published runtime while warm-up waits.
    let warm = control.udp_warm_task.lock().await;
    let (response, reload) = delay
        .measure(
            "204 No Content",
            publish_while_warm_blocked(&control, config_b, || {
                let registered = alive.registered_nodes();
                assert!(!registered.contains_key(&a) && registered.contains_key(&b));
            }),
        )
        .await;
    delay.success(response);
    assert!(
        history(a).is_empty() && last(a).is_none(),
        "retired A was recreated"
    );
    assert_eq!(delay.visible_delay("via").await, None);

    delay.exit = Some(replacement);
    // A measurement planned without a registration cannot acquire one at completion.
    let registration = alive.registered_nodes()[&b].clone();
    alive.remove_node(b);
    let (response, ()) = delay
        .measure("204 No Content", async {
            alive.register_node(b, registration.name, registration.raw_probe_address);
        })
        .await;
    delay.success(response);
    assert!(
        history(b).is_empty() && last(b).is_none(),
        "B had no registration at admission"
    );
    assert_eq!(delay.visible_delay("via").await, None);
    let (response, ()) = delay.measure("204 No Content", async {}).await;
    let measured = delay.success(response);
    assert_eq!(successes(b), [true]);
    assert_eq!(delay.visible_delay("via").await, Some(measured));

    drop(warm);
    assert!(reload.await.unwrap());
    assert!(!alive.registered_nodes().contains_key(&a));
    assert!(history(a).is_empty() && last(a).is_none());
    server.abort();
}

fn urltest_config(nodes: Vec<Node>) -> Config {
    let mut config = Config {
        groups: vec![Group {
            name: "pool".into(),
            policy: GroupPolicy::URLTest,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        }],
        nodes,
        ..Default::default()
    };
    config.global.nfqueue_enable = false;
    config.global.udp_warm_node_count = 0;
    config
}

fn peer_node(name: &str, peer: &Socks5Relay) -> Node {
    canonical_socks5(name, &peer.addr.to_string(), peer.addr.port(), None)
}

#[tokio::test]
async fn clash_node_delay_keeps_only_retained_physical_health() {
    let exit = socks5_http_exit().await;
    let node = peer_node("steady", &exit);
    let id = node.id;
    let mut config = urltest_config(vec![node]);
    let (control, api, server) = spawn_clash(config.clone()).await;
    let delay = ClashDelay::new(api, Some(exit), "/proxies/steady/delay", "delay");
    let runtime = || control.runtime_registry.read().get(&id).unwrap();
    let history = || {
        control
            .alive_set
            .get_probe_history(id, ProbeDomain::Tcp, IpVersion::V4)
    };

    let retained = runtime();
    config.nodes.push(Config::builtin_direct_node());
    let (response, ()) = delay
        .measure("204 No Content", async {
            reload(&control, config.clone()).await;
            assert!(Arc::ptr_eq(&retained, &runtime()));
        })
        .await;
    let measured = delay.success(response);
    let samples = history();
    assert_eq!(samples.len(), 1);
    assert!(samples[0].success);
    assert_eq!(delay.visible_delay("steady").await, Some(measured));

    // Tag metadata replaces the runtime while preserving the node ID and registration.
    config.nodes[0].tags.push("new-tag".into());
    let (response, ()) = delay
        .measure("204 No Content", async {
            reload(&control, config.clone()).await;
            assert!(!Arc::ptr_eq(&retained, &runtime()));
        })
        .await;
    delay.success(response);
    assert_eq!(history().len(), 1);
    assert_eq!(history()[0].timestamp, samples[0].timestamp);

    let retained = runtime();
    let mut rejected = config.clone();
    rejected.groups[0].nodes = vec![honk_config::config::DIRECT_NODE_ID];
    rejected.routing = changed_routing_config().routing;
    let (response, ()) = delay
        .measure("204 No Content", async {
            control
                .ebpf
                .write()
                .await
                .inject_routing_fault(RoutingPushPhase::Root, 1)
                .unwrap();
            assert!(
                !control
                    .reload_runtime_config(rejected, Default::default())
                    .await
            );
            assert!(Arc::ptr_eq(&retained, &runtime()));
            assert!(control.alive_set.registered_nodes().contains_key(&id));
        })
        .await;
    let measured = delay.success(response);
    assert_eq!(history().len(), 2, "rejection discarded an admitted delay");
    assert_eq!(delay.visible_delay("steady").await, Some(measured));

    config.groups[0].nodes = vec![honk_config::config::DIRECT_NODE_ID];
    let (unlocked, resume) = pause_after_publication(&control);
    let (response, (reload, before_completion)) = delay
        .measure("204 No Content", async {
            let executor = tokio::runtime::Handle::current();
            let plane = Arc::clone(&control);
            let reload = tokio::task::spawn_blocking(move || {
                executor.block_on(plane.reload_runtime_config(config, Default::default()))
            });
            unlocked.notified().await;
            assert!(
                Arc::ptr_eq(&retained, &runtime()),
                "membership alone changed"
            );
            (reload, history().len())
        })
        .await;
    delay.success(response);
    assert_eq!(
        history().len(),
        before_completion,
        "old delay wrote after publication"
    );
    assert!(history().is_empty());
    assert_eq!(delay.visible_delay("steady").await, None);
    resume.send(()).unwrap();
    assert!(reload.await.unwrap());
    server.abort();
}

fn pause_after_publication(
    control: &ControlPlane,
) -> (Arc<tokio::sync::Notify>, std::sync::mpsc::Sender<()>) {
    let unlocked = Arc::new(tokio::sync::Notify::new());
    let (resume_tx, resume) = std::sync::mpsc::channel();
    *control.clash_publication_pause.lock() = Some(crate::control::ClashPublicationPause {
        unlocked: Arc::clone(&unlocked),
        resume,
    });
    (unlocked, resume_tx)
}

#[tokio::test]
async fn clash_ungrouped_delay_only_updates_display_history() {
    let exit = socks5_http_exit().await;
    let node = peer_node("measured", &exit);
    let id = node.id;
    let mut config = urltest_config(vec![Config::builtin_block_node()]);
    config.nodes.push(node);
    let (control, api, server) = spawn_clash(config).await;
    let delay = ClashDelay::new(api, Some(exit), "/proxies/measured/delay", "delay");
    let alive = control.alive_set();
    let (domain, family) = (ProbeDomain::Tcp, IpVersion::V4);
    assert!(!alive.registered_nodes().contains_key(&id));
    alive.report_unavailable_forced(id, domain, family);
    alive.set_outbound_resolver(None);
    alive.set_ebpf_callback(Box::new(move |node, _, _, _, _| {
        assert_ne!(
            node, id,
            "display-only delay emitted a liveness notification"
        );
    }));
    let average = alive.get_moving_average(id, domain, family);
    let score = control.group_manager.read().score_cache_snapshot();
    assert_eq!(delay.visible_delay("measured").await, None);

    let mut measured = 0;
    for _ in 0..2 {
        let (response, ()) = delay.measure("204 No Content", async {}).await;
        measured = delay.success(response);
        assert_eq!(delay.visible_delay("measured").await, Some(measured));
    }
    let list = delay.document("/proxies").await;
    let history = &list["proxies"]["measured"]["history"];
    assert_eq!(history.as_array().unwrap().len(), 1);
    assert_eq!(history[0]["delay"], measured);
    assert!(history[0]["time"].as_str().is_some());
    let (failed, ()) = delay.measure("503 Service Unavailable", async {}).await;
    assert_eq!(failed.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        &delay.document("/proxies/measured").await["history"],
        history
    );
    assert!(!alive.registered_nodes().contains_key(&id));
    assert!(!alive.is_alive_for(id, domain, family));
    assert_eq!(alive.get_moving_average(id, domain, family), average);
    let health = alive.get_probe_history(id, domain, family);
    assert_eq!(health.len(), 1);
    assert!(!health[0].success);
    assert_eq!(control.group_manager.read().score_cache_snapshot(), score);

    let (response, successor) = delay
        .measure("204 No Content", async {
            alive.register_node(id, "measured".into(), Some("127.0.0.1:1".into()));
            assert_eq!(delay.visible_delay("measured").await, None);
            assert_eq!(alive.get_last_real_sample(id, domain, family), None);
            alive.remove_node(id);
            assert_eq!(delay.visible_delay("measured").await, None);
            let (fresh, ()) = delay.measure("204 No Content", async {}).await;
            let fresh = delay.success(fresh);
            let successor = delay.document("/proxies/measured").await;
            assert_eq!(successor["history"][0]["delay"], fresh);
            successor
        })
        .await;
    delay.success(response);
    assert_eq!(
        delay.document("/proxies/measured").await["history"],
        successor["history"]
    );
    assert!(alive.get_probe_history(id, domain, family).is_empty());
    server.abort();
}

#[tokio::test]
async fn clash_ungrouped_delay_survives_publications_that_retain_its_physical_leaf() {
    let exit = socks5_http_exit().await;
    let node = peer_node("measured", &exit);
    let id = node.id;
    let mut config = urltest_config(vec![Config::builtin_block_node()]);
    config.nodes.push(node);
    let (control, api, server) = spawn_clash(config.clone()).await;
    let delay = ClashDelay::new(api, Some(exit), "/proxies/measured/delay", "delay");
    let restored = Duration::from_millis(394);
    let restored_at = std::time::SystemTime::now() + Duration::from_secs(3600);
    control.alive_set.restore_latency(id, restored, restored_at);
    assert_eq!(delay.visible_delay("measured").await, Some(394));
    // A's first HEAD has already succeeded. B publishes before A's second HEAD
    // receives EOF, so A returns its own earlier first-round measurement.
    let (fallback, newer) = delay
        .measure_with_reply(None, async {
            let (response, ()) = delay.measure("204 No Content", async {}).await;
            let measured = delay.success(response);
            let node = delay.document("/proxies/measured").await;
            let history = node["history"].clone();
            assert_eq!(history[0]["delay"], measured);
            assert_ne!(
                history[0]["time"],
                chrono::DateTime::<chrono::Utc>::from(restored_at).to_rfc3339()
            );
            history
        })
        .await;
    delay.success(fallback);
    assert_eq!(delay.document("/proxies/measured").await["history"], newer);
    assert_eq!(
        delay.document("/proxies").await["proxies"]["measured"]["history"],
        newer
    );

    for full_reload in [false, true] {
        let before = delay.document("/proxies/measured").await;
        let generation = control.runtime_registry.read().generation();
        let (response, ()) = delay
            .measure("204 No Content", async {
                if full_reload {
                    config.nodes.push(Config::builtin_direct_node());
                    reload(&control, config.clone()).await;
                } else {
                    control.reload_group_manager().await.unwrap();
                }
                assert_eq!(
                    control.runtime_registry.read().generation() != generation,
                    full_reload
                );
                assert!(!control.alive_set.registered_nodes().contains_key(&id));
                assert_eq!(
                    delay.document("/proxies/measured").await["history"],
                    before["history"]
                );
            })
            .await;
        let measured = delay.success(response);
        let after = delay.document("/proxies/measured").await;
        assert_eq!(after["history"][0]["delay"], measured);
        assert_ne!(after["history"][0]["time"], before["history"][0]["time"]);
    }
    assert_eq!(
        control
            .alive_set
            .get_last_real_sample(id, ProbeDomain::Tcp, IpVersion::V4),
        Some((restored, restored_at))
    );
    assert!(
        control
            .alive_set
            .get_probe_history(id, ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
    server.abort();
}

#[tokio::test]
async fn clash_ungrouped_delay_cannot_credit_a_replaced_or_removed_leaf() {
    let exit = socks5_http_exit().await;
    let mut config = urltest_config(vec![Config::builtin_block_node()]);
    config.nodes.push(peer_node("measured", &exit));
    let id = config.nodes[1].id;
    let (control, api, server) = spawn_clash(config.clone()).await;
    let delay = ClashDelay::new(api, Some(exit), "/proxies/measured/delay", "delay");
    let (response, ()) = delay.measure("204 No Content", async {}).await;
    let measured = delay.success(response);
    assert_eq!(delay.visible_delay("measured").await, Some(measured));
    config.nodes[1].tags.push("replacement".into());
    let (response, ()) = delay
        .measure("204 No Content", async {
            reload(&control, config.clone()).await;
            assert_eq!(delay.visible_delay("measured").await, None);
        })
        .await;
    delay.success(response);
    assert_eq!(delay.visible_delay("measured").await, None);
    let (response, ()) = delay.measure("204 No Content", async {}).await;
    let measured = delay.success(response);
    assert_eq!(delay.visible_delay("measured").await, Some(measured));

    // Only the manager changes. Removing and restoring the leaf here keeps
    // the same registry runtime throughout, so a runtime check alone would pass.
    let (response, ()) = delay
        .measure("204 No Content", async {
            let mut absent = config.clone();
            absent.nodes.retain(|node| node.id != id);
            *control.config.write().await = Arc::new(absent);
            control.reload_group_manager().await.unwrap();
            *control.config.write().await = Arc::new(config.clone());
            control.reload_group_manager().await.unwrap();
        })
        .await;
    delay.success(response);
    assert_eq!(delay.visible_delay("measured").await, None);

    let (response, ()) = delay
        .measure("204 No Content", async {
            let mut removed = config.clone();
            removed.nodes.retain(|node| node.id != id);
            reload(&control, removed).await;
        })
        .await;
    delay.success(response);
    let removed = delay
        .client
        .get(format!("http://{api}/proxies/measured"))
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), StatusCode::NOT_FOUND);
    reload(&control, config).await;
    assert_eq!(delay.visible_delay("measured").await, None);
    assert!(
        control
            .alive_set
            .get_probe_history(id, ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
    server.abort();
}

#[tokio::test]
async fn clash_group_delay_cannot_credit_or_reselect_after_manager_only_rebuild() {
    let old_exit = socks5_http_exit().await;
    let new_exit = socks5_http_exit().await;
    let old = peer_node("old", &old_exit);
    let new = peer_node("new", &new_exit);
    let (old_id, new_id) = (old.id, new.id);
    let mut config = urltest_config(vec![old]);
    config.nodes.push(new);
    let (control, api, server) = spawn_clash(config).await;
    let mut delay = ClashDelay::new(api, Some(old_exit), "/group/pool/delay", "old");
    let generation = control.runtime_registry.read().generation();
    let (unlocked, resume_tx) = pause_after_publication(&control);
    let (response, (rebuild, resume_tx)) = delay
        .measure("204 No Content", async {
            Arc::make_mut(&mut *control.config.write().await).groups[0].nodes = vec![new_id];
            let runtime = tokio::runtime::Handle::current();
            let plane = Arc::clone(&control);
            let rebuild = tokio::task::spawn_blocking(move || {
                runtime.block_on(plane.reload_group_manager()).unwrap();
            });
            unlocked.notified().await;
            (rebuild, resume_tx)
        })
        .await;
    delay.success(response);
    assert_eq!(control.runtime_registry.read().generation(), generation);
    assert_eq!(delay.visible_delay("old").await, None);
    assert!(
        control
            .alive_set
            .get_probe_history(old_id, ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
    assert_eq!(
        control.group_manager.read().get_urltest_selection("pool"),
        None
    );
    assert!(control.alive_set.is_urltest_group_idle("pool"));
    resume_tx.send(()).unwrap();
    rebuild.await.unwrap();

    delay.exit = Some(new_exit);
    delay.result_name = "new";
    let (response, ()) = delay.measure("204 No Content", async {}).await;
    let measured = delay.success(response);
    assert_eq!(delay.visible_delay("new").await, Some(measured));
    assert_eq!(
        control
            .group_manager
            .read()
            .get_urltest_selection("pool")
            .as_deref(),
        Some("new")
    );
    assert!(!control.alive_set.is_urltest_group_idle("pool"));
    server.abort();
}

#[tokio::test]
async fn clash_unregistered_direct_delay_survives_reload_but_not_registration_aba() {
    let direct = Config::builtin_direct_node();
    let id = direct.id;
    let mut config = urltest_config(vec![Config::builtin_block_node()]);
    config.nodes.push(direct);
    let (control, api, server) = spawn_clash(config.clone()).await;
    let delay = ClashDelay::new(api, None, "/proxies/direct/delay", "delay");
    let runtime = || control.runtime_registry.read().get(&id).unwrap();
    let retained = runtime();
    let registered = || control.alive_set.registered_nodes().contains_key(&id);
    assert!(!registered());

    config
        .nodes
        .push(canonical_socks5("unused", "127.0.0.1", 1, None));
    let (response, ()) = delay
        .measure("204 No Content", async {
            reload(&control, config.clone()).await;
            assert!(!registered());
            assert!(Arc::ptr_eq(&runtime(), &retained));
        })
        .await;
    let measured = delay.success(response);
    assert_eq!(delay.visible_delay("direct").await, Some(measured));

    let mut grouped = config.clone();
    grouped.groups[0].nodes = vec![id];
    let (response, ()) = delay
        .measure("204 No Content", async {
            reload(&control, grouped).await;
            assert!(registered());
            reload(&control, config.clone()).await;
            assert!(!registered());
            assert!(Arc::ptr_eq(&runtime(), &retained));
        })
        .await;
    delay.success(response);
    assert!(
        control
            .alive_set
            .get_probe_history(id, ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
    assert_eq!(delay.visible_delay("direct").await, None);

    // DIRECT has no registration to remove in this physical ABA.
    let mut without_direct = config.clone();
    without_direct.nodes.retain(|node| node.id != id);
    let (response, ()) = delay
        .measure("204 No Content", async {
            reload(&control, without_direct).await;
            assert!(control.runtime_registry.read().get(&id).is_none());
            reload(&control, config).await;
            assert!(!registered());
            assert!(!Arc::ptr_eq(&runtime(), &retained));
        })
        .await;
    delay.success(response);
    assert!(
        control
            .alive_set
            .get_probe_history(id, ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
    assert_eq!(delay.visible_delay("direct").await, None);
    server.abort();
}

#[tokio::test]
async fn clash_group_delay_cannot_select_a_successor_urltest_member() {
    delay_cannot_select_a_successor("/group/pool/delay", "old", "new").await;
}

#[tokio::test]
async fn clash_proxy_group_delay_projects_its_captured_urltest_member() {
    delay_cannot_select_a_successor("/proxies/pool/delay", "delay", "delay").await;
}

async fn delay_cannot_select_a_successor(
    path: &'static str,
    old_key: &'static str,
    new_key: &'static str,
) {
    let old = socks5_http_exit().await;
    let new = socks5_http_exit().await;
    let old_node = peer_node("old", &old);
    let old_id = old_node.id;
    let (control, api, server) = spawn_clash(urltest_config(vec![old_node])).await;
    let mut delay = ClashDelay::new(api, Some(old), path, old_key);
    let successor = urltest_config(vec![peer_node("new", &new), Config::builtin_block_node()]);
    let choice = || control.group_manager.read().get_urltest_selection("pool");
    let idle = || control.alive_set.is_urltest_group_idle("pool");

    let warm = control.udp_warm_task.lock().await;
    let (response, reload) = delay
        .measure(
            "204 No Content",
            publish_while_warm_blocked(&control, successor, || {
                assert_eq!(choice(), None);
                assert!(idle());
            }),
        )
        .await;
    delay.success(response);
    assert!(
        control
            .alive_set()
            .get_probe_history(old_id, ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
    assert_eq!(
        choice(),
        None,
        "the old measurement selected a successor member"
    );
    assert!(idle(), "the old measurement activated the successor group");
    drop(warm);
    assert!(reload.await.unwrap());

    delay.exit = Some(new);
    delay.result_name = new_key;
    if new_key == "delay" {
        let (failed, ()) = delay.measure("500 Internal Server Error", async {}).await;
        assert_eq!(failed.0, StatusCode::SERVICE_UNAVAILABLE);
    }
    let (response, ()) = delay.measure("204 No Content", async {}).await;
    delay.success(response);
    assert_eq!(choice().as_deref(), Some("new"));
    assert!(!idle());
    server.abort();
}
