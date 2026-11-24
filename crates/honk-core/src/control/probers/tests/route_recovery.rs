use super::*;
use crate::control::{
    connection::ControlPlaneHandle,
    tests::{
        store_active_tcp_flow,
        support::{TestRetirement, test_dns_forwarder},
    },
};
use futures::FutureExt;
use honk_config::group::{Group, GroupPolicy};
use honk_outbound::group::{OwnedTarget, Target};
use honk_outbound::proxy::{DialFailureScope, dial_failure_scope};
use honk_outbound::runtime::OutboundRuntimeRegistry;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

mod udp;

const REFUSALS: usize = 10;
const EXIT_HOST: &str = "exit.route-recovery.invalid";
const EXIT_PORT: u16 = 1842;

fn socks5_node(name: &str, host: &str, port: u16) -> Node {
    let mut node = Node {
        name: name.into(),
        address: format!("{host}:{port}"),
        host: host.into(),
        port,
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

async fn serve_front(
    listener: TcpListener,
    exit: SocketAddr,
    refusals: usize,
    attempts: Arc<AtomicUsize>,
    mut confirmation: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
) {
    for attempt in 0..=refusals {
        let (mut stream, _) = listener.accept().await.unwrap();
        attempts.fetch_add(1, Ordering::Relaxed);
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut connect = [0; 5];
        stream.read_exact(&mut connect).await.unwrap();
        assert_eq!(&connect[..4], &[5, 1, 0, 3]);
        assert_eq!(usize::from(connect[4]), EXIT_HOST.len());
        let mut target = [0; EXIT_HOST.len() + 2];
        stream.read_exact(&mut target).await.unwrap();
        assert_eq!(&target[..EXIT_HOST.len()], EXIT_HOST.as_bytes());
        assert_eq!(&target[EXIT_HOST.len()..], &EXIT_PORT.to_be_bytes());
        if attempt < refusals {
            stream
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            continue;
        }
        // The advertised exit address exists only inside this front's CONNECT handling.
        let mut upstream = TcpStream::connect(exit).await.unwrap();
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        if let Some((received, allow)) = confirmation.take() {
            received.send(()).unwrap();
            allow.await.unwrap();
        }
        tokio::io::copy_bidirectional(&mut stream, &mut upstream)
            .await
            .unwrap();
    }
}

fn selected_route(manager: &GroupManager) -> OwnedTarget {
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let mut plan = manager.selection_plan_for_target("root", &context);
    assert_eq!(plan.entries.len(), 1);
    let entry = plan.entries.pop().unwrap();
    manager.own_target(Target {
        node: entry.node,
        route: entry.route,
    })
}

async fn expect_payload_reply(
    client: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    peer: &mut TcpStream,
) {
    client.write_u8(b'q').await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(peer.read_u8().await.unwrap(), b'q');
    peer.write_u8(b'r').await.unwrap();
    assert_eq!(client.read_u8().await.unwrap(), b'r');
}

async fn accept_business(
    handle: &ControlPlaneHandle,
    origin: &TcpListener,
) -> (TcpStream, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let dst = origin.local_addr().unwrap();
    let client = TcpStream::connect(dst).await.unwrap();
    let (socket, src) = origin.accept().await.unwrap();
    store_active_tcp_flow(handle, dst, src).await.unwrap();
    let handle = handle.clone();
    (
        client,
        tokio::spawn(async move { handle.serve_connection(socket, src).await }),
    )
}

#[tokio::test]
async fn configured_routed_http_recovery_requires_a_valid_response() {
    for (response, recovered) in [
        (Reply::Valid, true),
        (Reply::Unavailable, false),
        (Reply::Malformed, false),
        (Reply::Silent, false),
    ] {
        check_route_recovery(response, recovered).await;
    }
}

#[tokio::test]
async fn configured_recovery_reopens_only_the_failed_route_with_a_working_sibling() {
    check_route_recovery(Reply::ValidWithSibling, true).await;
}

#[tokio::test]
async fn only_the_sole_root_without_final_can_revive_a_failed_route_with_business() {
    check_route_recovery(Reply::SoleTraffic, true).await;
}

#[tokio::test]
async fn routed_http_recovery_ignores_an_old_generation_response() {
    check_route_recovery(Reply::Replace, false).await;
}

#[tokio::test]
async fn routed_http_recovery_shutdown_cancels_and_joins_the_exchange() {
    check_route_recovery(Reply::Cancel, false).await;
}

#[tokio::test]
async fn no_configured_http_target_never_dials_for_route_recovery() {
    check_route_recovery(Reply::Unconfigured, false).await;
}

#[tokio::test]
async fn routed_http_recovery_does_not_bypass_local_resolution_refusal() {
    check_route_recovery(Reply::Refused, false).await;
}

#[derive(Clone, Copy, Debug)]
enum Reply {
    Valid,
    ValidWithSibling,
    SoleTraffic,
    Unavailable,
    Malformed,
    Silent,
    Replace,
    Cancel,
    Unconfigured,
    Refused,
}

async fn check_route_recovery(response: Reply, recovered: bool) {
    tokio::time::timeout(Duration::from_secs(8), async {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = origin.local_addr().unwrap();
        let relay = crate::test_support::socks5_relay().await;
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let leaf = socks5_node("front", "127.0.0.1", front.local_addr().unwrap().port());
        let exit = socks5_node("exit", EXIT_HOST, EXIT_PORT);
        let (leaf_id, exit_id) = (leaf.id, exit.id);
        let front_attempts = Arc::new(AtomicUsize::new(0));
        let (confirmation, gate) = if matches!(response, Reply::SoleTraffic) {
            let (received, at_front) = oneshot::channel();
            let (release, allow) = oneshot::channel();
            (Some((received, allow)), Some((at_front, release)))
        } else {
            (None, None)
        };
        let front = tokio::spawn(serve_front(
            front,
            relay.addr,
            REFUSALS,
            Arc::clone(&front_attempts),
            confirmation,
        ));
        let exit_name = exit.name.clone();
        let mut nodes = vec![leaf, exit];
        let mut members = vec![leaf_id];
        let sibling = if matches!(response, Reply::ValidWithSibling) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let node = socks5_node(
                "sibling",
                "127.0.0.1",
                listener.local_addr().unwrap().port(),
            );
            let id = node.id;
            let attempts = Arc::new(AtomicUsize::new(0));
            let task = tokio::spawn(serve_front(
                listener,
                relay.addr,
                0,
                Arc::clone(&attempts),
                None,
            ));
            members.push(id);
            nodes.push(node);
            Some((id, attempts, task))
        } else {
            None
        };
        let mut config = Config {
            groups: vec![Group {
                name: "root".into(),
                policy: GroupPolicy::Fallback,
                nodes: members,
                exit: Some(exit_name),
                final_outbound: Some("block".into()),
                check_url: (!matches!(response, Reply::Unconfigured | Reply::SoleTraffic)).then(
                    || {
                        let port = addr.port();
                        let fallback = if matches!(response, Reply::Refused) {
                            ",127.0.0.1,127.0.0.2,127.0.0.3"
                        } else {
                            ""
                        };
                        format!("http://check.invalid:{port}/a/../health?q=1#fragment{fallback}")
                    },
                ),
                ..Default::default()
            }],
            nodes,
            ..Default::default()
        };
        config.global.tcp_check_url.clear();
        config.global.tcp_check_http_method = "GET".into();
        let plane = matches!(response, Reply::SoleTraffic).then(|| {
            config.ensure_builtin_nodes();
            config.routing.default_outbound = "root".into();
            config.global.dial_mode = "ip".into();
            config.global.nfqueue_enable = false;
            let router = Router::from_config(&config.routing).unwrap();
            ControlPlane::new(
                config.clone(),
                Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
                router,
                Arc::new(ProxyRegistry::default_resolver().unwrap()),
                DnsResolver::new(&Default::default()).unwrap(),
                test_dns_forwarder(),
            )
            .unwrap()
        });
        let alive = plane
            .as_ref()
            .map_or_else(|| Arc::new(AliveDialerSet::new()), ControlPlane::alive_set);
        let resolved = Arc::new(AtomicBool::new(false));
        let resolve_called = Arc::clone(&resolved);
        alive.set_resolver(Arc::new(move |host, port| {
            let resolve_called = Arc::clone(&resolve_called);
            Box::pin(async move {
                assert!(!matches!(response, Reply::Unconfigured));
                assert_eq!(host, "check.invalid");
                assert_eq!(port, addr.port());
                resolve_called.store(true, Ordering::Relaxed);
                if matches!(response, Reply::Refused) {
                    return Err(honk_outbound::proxy::PacketRejection::Policy.into());
                }
                Ok(vec![
                    SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
                    addr,
                ])
            })
        }));
        let make_manager = |config: &Config| {
            Arc::new(GroupManager::with_alive_set(
                &config.groups,
                &config.nodes,
                Some(Arc::clone(&alive)),
            ))
        };
        let (groups, proxy, runtimes, config) = if let Some(plane) = &plane {
            (
                plane.group_manager(),
                plane.proxy_registry(),
                plane.runtime_registry(),
                plane.config_handle(),
            )
        } else {
            let manager = make_manager(&config);
            manager.publish_route_health();
            let groups = Arc::new(parking_lot::RwLock::new(manager));
            let proxy = Arc::new(ProxyRegistry::default_resolver().unwrap());
            let generation = Arc::new(OutboundRuntimeRegistry::build(&config.nodes).unwrap());
            let runtimes = Arc::new(parking_lot::RwLock::new(generation));
            (
                groups,
                proxy,
                runtimes,
                Arc::new(RwLock::new(Arc::new(config))),
            )
        };
        let manager = groups.read().clone();
        let generation = runtimes.read().clone();
        let target = selected_route(&manager);
        let route = *target.route().unwrap();
        assert_eq!(route.hops(), [leaf_id, exit_id]);
        alive.set_route_http_probe(Arc::new(ProxyHttpProber::new(
            Arc::clone(&config),
            Arc::clone(&proxy),
            Arc::clone(&runtimes),
            "HEAD".into(),
            Arc::clone(&groups),
        )));

        let revision = manager.route_health_revision("root");
        let mut last_failure = None;
        for count in 1..=REFUSALS {
            let stamp = revision.admit();
            let error = proxy
                .dial_ref(
                    Arc::clone(&generation),
                    target.dial_ref(),
                    addr,
                    None,
                    Duration::from_secs(1),
                )
                .await
                .unwrap_err();
            assert_eq!(
                dial_failure_scope(error.as_ref()),
                DialFailureScope::Prefix(1)
            );
            assert!(manager.report_route_failure(
                "root",
                &target,
                IpVersion::V4,
                stamp,
                error.as_ref(),
            ));
            if count < REFUSALS {
                assert!(manager.route_prefix_available(&route, IpVersion::V4));
                assert_eq!(selected_route(&manager).key(), target.key());
            } else {
                last_failure = Some(error);
            }
        }
        assert_eq!(front_attempts.load(Ordering::Relaxed), REFUSALS);
        assert!(!manager.route_prefix_available(&route, IpVersion::V4));
        assert!(manager.route_prefix_available(&route, IpVersion::V6));
        let alternate = selected_route(&manager);
        let block = honk_config::config::BLOCK_NODE_ID;
        let sibling_id = sibling.as_ref().map(|(id, _, _)| *id);
        assert_eq!(alternate.node.id, sibling_id.unwrap_or(block));

        // The production ingress sees the same failed prefix before and after
        // the sole-leaf policy becomes applicable.
        if let Some(plane) = plane {
            let handle = plane.spawn_handle();
            let retirement = TestRetirement::start(&handle);
            let (mut client, blocked) = accept_business(&handle, &origin).await;
            finish_server(blocked).await.unwrap();
            assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            assert_eq!(front_attempts.load(Ordering::Relaxed), REFUSALS);
            assert!(relay.requests.lock().is_empty());
            assert!(origin.accept().now_or_never().is_none());
            drop(client);

            let dns = plane.dns_controller.runtime_provider();
            let before = dns.current_generation().get();
            let retired_receipt = revision.admit();
            let mut candidate = config.read().await.as_ref().clone();
            candidate.groups[0].final_outbound = None;
            assert!(
                plane
                    .reload_runtime_config(candidate, Default::default())
                    .await
            );
            assert_eq!(dns.current_generation().get(), before + 1);
            let active = runtimes.read().clone();
            for id in [leaf_id, exit_id] {
                assert!(Arc::ptr_eq(
                    &generation.get(&id).unwrap(),
                    &active.get(&id).unwrap(),
                ));
            }
            let current = groups.read().clone();
            assert!(!Arc::ptr_eq(&manager, &current));
            assert!(!manager.report_route_failure(
                "root",
                &target,
                IpVersion::V4,
                retired_receipt,
                last_failure.as_ref().unwrap().as_ref(),
            ));
            let manager = current;
            assert!(!manager.route_prefix_available(&route, IpVersion::V4));
            assert_eq!(selected_route(&manager).key(), target.key());

            let (at_front, release) = gate.unwrap();
            let (mut client, serving) = accept_business(&handle, &origin).await;
            at_front.await.unwrap();
            assert_eq!(front_attempts.load(Ordering::Relaxed), REFUSALS + 1);
            // The first proxy accepted CONNECT, but the exit has not replied yet.
            assert!(!manager.route_prefix_available(&route, IpVersion::V4));
            assert!(relay.requests.lock().is_empty());
            release.send(()).unwrap();
            let (mut peer, _) = origin.accept().await.unwrap();
            expect_payload_reply(&mut client, &mut peer).await;
            assert!(manager.route_prefix_available(&route, IpVersion::V4));
            assert!(!resolved.load(Ordering::Relaxed));
            assert_eq!(*relay.requests.lock(), [addr]);
            client.shutdown().await.unwrap();
            peer.shutdown().await.unwrap();
            drop(peer);
            drop(client);
            finish_server(serving).await.unwrap();
            finish_server(front).await;
            plane.stop_udp_warm_coordinator().await;
            plane.stop_selector_warm_coordinator().await;
            alive.shutdown_health_checks().await.unwrap();
            retirement.join(&handle).await.unwrap();
            return;
        }

        let mut expected_exit_requests = Vec::new();
        if let Some((id, attempts, sibling_task)) = sibling {
            let sibling_route = alternate.route().unwrap();
            assert_eq!(sibling_route.hops(), [id, exit_id]);
            assert!(manager.route_prefix_available(sibling_route, IpVersion::V4));
            let business = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let business_addr = business.local_addr().unwrap();
            let mut stream = proxy
                .dial_ref(
                    Arc::clone(&generation),
                    alternate.dial_ref(),
                    business_addr,
                    None,
                    Duration::from_secs(1),
                )
                .await
                .unwrap();
            let (mut peer, _) = business.accept().await.unwrap();
            expect_payload_reply(&mut stream.stream, &mut peer).await;
            drop(stream);
            drop(peer);
            finish_server(sibling_task).await;
            expected_exit_requests.push(business_addr);
            assert_eq!(*relay.requests.lock(), expected_exit_requests);
            assert_eq!(attempts.load(Ordering::Relaxed), 1);
            assert_eq!(front_attempts.load(Ordering::Relaxed), REFUSALS);
            assert!(!manager.route_prefix_available(&route, IpVersion::V4));
        }
        if matches!(response, Reply::Unconfigured | Reply::Refused) {
            alive.run_health_check_cycle(Duration::from_secs(2)).await;
            assert_eq!(
                resolved.load(Ordering::Relaxed),
                matches!(response, Reply::Refused)
            );
            alive.shutdown_health_checks().await.unwrap();
            assert!(!front.is_finished(), "unexpected recovery dial");
            assert_eq!(front_attempts.load(Ordering::Relaxed), REFUSALS);
            assert!(relay.requests.lock().is_empty());
            assert!(origin.accept().now_or_never().is_none());
            assert!(!manager.route_prefix_available(&route, IpVersion::V4));
            front.abort();
            assert!(front.await.unwrap_err().is_cancelled());
            return;
        }
        let cycle = tokio::spawn({
            let alive = Arc::clone(&alive);
            let timeout = if matches!(response, Reply::Cancel) {
                Duration::from_secs(30)
            } else {
                Duration::from_secs(2)
            };
            async move { alive.run_health_check_cycle(timeout).await }
        });

        let (mut peer, _) = origin.accept().await.unwrap();
        assert_eq!(front_attempts.load(Ordering::Relaxed), REFUSALS + 1);
        let request = read_request_head(&mut peer).await;
        assert!(
            request.starts_with("GET /a/../health?q=1 HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains(&format!("\r\nHost: check.invalid:{}\r\n", addr.port())));
        assert!(!manager.route_prefix_available(&route, IpVersion::V4));
        if matches!(response, Reply::Replace) {
            let mut accepted = config.write().await;
            let mut published = groups.write();
            let mut runtime = runtimes.write();
            let mut replacement = (**accepted).clone();
            replacement.groups[0].check_url = Some("http://replacement.invalid/health".into());
            let manager = make_manager(&replacement);
            *runtime = Arc::new(OutboundRuntimeRegistry::build(&replacement.nodes).unwrap());
            *accepted = Arc::new(replacement);
            manager.publish_route_health();
            *published = manager;
        }
        let reply: &[u8] = match response {
            Reply::Valid | Reply::ValidWithSibling | Reply::Replace => {
                b"HTTP/1.1 204 No Content\r\n\r\n"
            }
            Reply::Unavailable => b"HTTP/1.1 503 Service Unavailable\r\n\r\n",
            Reply::Malformed => b"HTTP/1.1 204 No Content\r\ninvalid header\r\n\r\n",
            Reply::Silent | Reply::Cancel => b"",
            Reply::Unconfigured | Reply::Refused | Reply::SoleTraffic => unreachable!(),
        };
        if matches!(response, Reply::Cancel) {
            alive.shutdown_health_checks().await.unwrap();
        } else if !reply.is_empty() {
            peer.write_all(reply).await.unwrap();
        }
        cycle.await.unwrap();
        if !matches!(response, Reply::Cancel) {
            alive.shutdown_health_checks().await.unwrap();
        }
        assert_eq!(
            peer.read(&mut [0]).await.unwrap(),
            0,
            "one configured request per stream"
        );
        drop(peer);
        finish_server(front).await;
        expected_exit_requests.push(addr);
        assert_eq!(
            *relay.requests.lock(),
            expected_exit_requests,
            "{response:?}"
        );
        let manager = groups.read();
        assert_eq!(
            manager.route_prefix_available(&route, IpVersion::V4),
            recovered,
            "{response:?}"
        );
        assert_eq!(
            selected_route(&manager).node.id,
            sibling_id.unwrap_or(if recovered { leaf_id } else { block })
        );
    })
    .await
    .unwrap();
}
