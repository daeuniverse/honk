use super::super::lifecycle::{OwnedTasks, retain_error};
use super::super::{ControlCommand, ControlPlane, ReloadOutcome, ReloadReply};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommandAction {
    Continue,
    Shutdown,
}

type Reply<T> = (
    tokio::sync::oneshot::Sender<T>,
    tokio::sync::oneshot::Receiver<T>,
);

pub(super) enum CommandReply {
    Reload(Reply<ReloadReply>),
    Subscription(Reply<crate::subscription::SubscriptionMergeReply>),
    #[cfg(any(feature = "native-api", feature = "clash-api"))]
    Selector(
        Reply<Result<super::super::client::SelectionResult, super::super::client::ControlError>>,
    ),
    #[cfg(all(feature = "native-api", feature = "clash-api"))]
    Mode(Reply<Result<crate::mode::ModeState, super::super::client::ControlError>>),
}

pub(super) fn separate_reply(command: &mut ControlCommand) -> Option<CommandReply> {
    fn replace<T>(sender: &mut tokio::sync::oneshot::Sender<T>) -> Reply<T> {
        let (internal, receiver) = tokio::sync::oneshot::channel();
        (std::mem::replace(sender, internal), receiver)
    }
    Some(match command {
        ControlCommand::ReloadConfig { result, .. } => CommandReply::Reload(replace(result)),
        ControlCommand::MergeSubscription { result, .. } => {
            CommandReply::Subscription(replace(result))
        }
        #[cfg(any(feature = "native-api", feature = "clash-api"))]
        ControlCommand::SetSelector { reply, .. } => CommandReply::Selector(replace(reply)),
        #[cfg(all(feature = "native-api", feature = "clash-api"))]
        ControlCommand::SetRuntimeMode { reply, .. } => CommandReply::Mode(replace(reply)),
        ControlCommand::NetworkChanged | ControlCommand::Shutdown => return None,
    })
}

impl CommandReply {
    pub(super) fn forward(self) -> bool {
        fn forward<T>((sender, mut receiver): Reply<T>) {
            if let Ok(result) = receiver.try_recv() {
                let _ = sender.send(result);
            }
        }
        match self {
            Self::Reload((sender, mut receiver)) => {
                let Ok(reply) = receiver.try_recv() else {
                    return false;
                };
                let accepted = reply.outcome.accepted();
                if sender.send(reply).is_err() && accepted {
                    tracing::error!("packet reload lost its supervisor handoff");
                    return false;
                }
            }
            Self::Subscription(reply) => forward(reply),
            #[cfg(any(feature = "native-api", feature = "clash-api"))]
            Self::Selector(reply) => forward(reply),
            #[cfg(all(feature = "native-api", feature = "clash-api"))]
            Self::Mode(reply) => forward(reply),
        }
        true
    }
}

pub(super) const COMMAND_MEMORY: usize =
    size_of::<ReloadReply>() + size_of::<crate::subscription::SubscriptionMergeReply>() + 1024;

pub(super) async fn start(plane: &mut ControlPlane) -> OwnedTasks {
    plane.configure_health_loop().await;
    plane.start_userspace_maintenance().await
}

pub(super) async fn handle_command(
    plane: &mut ControlPlane,
    command: ControlCommand,
) -> CommandAction {
    let closing = plane
        .shutdown_requested
        .load(std::sync::atomic::Ordering::Acquire);
    match command {
        #[cfg(any(feature = "native-api", feature = "clash-api"))]
        ControlCommand::SetSelector { request, reply } => {
            let result = if closing {
                Err(super::super::client::ControlError::Unavailable)
            } else {
                plane.apply_selector_request(request).await
            };
            let _ = reply.send(result);
        }
        #[cfg(all(feature = "native-api", feature = "clash-api"))]
        ControlCommand::SetRuntimeMode { reply, .. } => {
            let _ = reply.send(Err(super::super::client::ControlError::Unsupported));
        }
        ControlCommand::ReloadConfig {
            request_id, result, ..
        } => {
            tracing::warn!(
                request_id,
                "packet endpoint config reload requires an unavailable backend publication owner; retaining configuration"
            );
            let _ = result.send(ReloadReply {
                outcome: ReloadOutcome::Rejected,
                authorized: Vec::new(),
            });
        }
        ControlCommand::MergeSubscription {
            subscription_id,
            result,
            ..
        } => {
            let config = plane.config.read().await;
            tracing::warn!(%subscription_id, "packet endpoint subscription merge requires an unavailable backend publication owner; retaining configuration");
            let _ = result.send(crate::subscription::SubscriptionMergeReply {
                outcome: ReloadOutcome::Rejected,
                node_count: config
                    .nodes
                    .iter()
                    .filter(|node| node.subscription_id == Some(subscription_id))
                    .count(),
                authorized: Vec::new(),
                rejection: Some("packet_endpoint_unsupported"),
            });
        }
        ControlCommand::NetworkChanged => {
            if !closing {
                plane.alive_set.notify_network_change();
            }
        }
        ControlCommand::Shutdown => return CommandAction::Shutdown,
    }
    CommandAction::Continue
}

pub(super) async fn wait_owned<F: Future>(
    mut operation: std::pin::Pin<&mut F>,
    label: &'static str,
) -> F::Output {
    match tokio::time::timeout(std::time::Duration::from_secs(5), operation.as_mut()).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(
                label,
                "Packet cleanup exceeded its deadline; retaining ownership until join"
            );
            operation.await
        }
    }
}

pub(super) async fn shutdown(
    plane: &mut ControlPlane,
    mut failure: Option<anyhow::Error>,
    udp: Option<super::super::udp_endpoint::UdpShutdown>,
) -> anyhow::Result<()> {
    plane
        .shutdown_requested
        .store(true, std::sync::atomic::Ordering::Release);
    plane.drain_tracker.start_rejecting();
    #[cfg(feature = "native-api")]
    plane.publish_phase(if failure.is_some() {
        super::super::EnginePhase::Failed
    } else {
        super::super::EnginePhase::Draining
    });
    retain_error(
        &mut failure,
        wait_owned(
            std::pin::pin!(plane.alive_set.shutdown_health_checks()),
            "health probes",
        )
        .await
        .map_err(anyhow::Error::from),
    );
    if let Some(health) = plane.health_task.take() {
        retain_error(
            &mut failure,
            wait_owned(std::pin::pin!(health), "health owner")
                .await
                .map_err(anyhow::Error::from),
        );
    }
    #[cfg(feature = "native-api")]
    if let Some(owner) = &plane.native_owner {
        retain_error(
            &mut failure,
            wait_owned(std::pin::pin!(owner.pause_probes()), "native probes").await,
        );
    }
    #[cfg(feature = "clash-api")]
    {
        let mut download = plane.ui_download.lock().await;
        if let Some(task) = download.as_mut() {
            retain_error(&mut failure, task.stop_and_join().await);
        }
        download.take();
    }
    for (joined, owner) in [
        (
            plane.stop_udp_warm_coordinator().await,
            "UDP warm coordinator",
        ),
        (
            plane.stop_selector_warm_coordinator().await,
            "Selector warm coordinator",
        ),
    ] {
        if !joined {
            failure.get_or_insert_with(|| anyhow::anyhow!("{owner} cleanup failed"));
        }
    }
    let udp = match udp {
        Some(udp) => udp,
        None => plane.udp_pool.shutdown().await,
    };
    if !udp.joined || !udp.graceful {
        failure.get_or_insert_with(|| anyhow::anyhow!("packet UDP cleanup failed"));
    }
    retain_error(
        &mut failure,
        wait_owned(std::pin::pin!(plane.stop_packet_epoch()), "outbound owners").await,
    );
    retain_error(
        &mut failure,
        wait_owned(
            std::pin::pin!(plane.finalize_userspace_shutdown()),
            "DNS and persistence",
        )
        .await,
    );
    let registry = plane.runtime_registry.read().clone();
    wait_owned(
        std::pin::pin!(registry.shutdown_wireguard_tunnels()),
        "WireGuard owners",
    )
    .await;
    if registry.tasks_failed() {
        failure.get_or_insert_with(|| anyhow::anyhow!("packet outbound cleanup failed"));
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::tests::support::control_plane;
    use honk_config::{Config, node::Group};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::oneshot;

    fn config() -> Config {
        let mut config = Config::default();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
        config.global.preconnect_node_count = 0;
        config.global.udp_warm_node_count = 0;
        config
    }

    #[tokio::test]
    async fn reload_merge_and_shutdown_reply_without_backend_access() {
        let mut config = config();
        let subscription_id = uuid::Uuid::new_v4();
        let node = crate::control::tests::support::canonical_socks5(
            "retained",
            "127.0.0.1",
            9,
            Some(subscription_id),
        );
        config.nodes.push(node);
        let mut plane = control_plane(config);
        let old = plane.config.read().await.clone();
        let backend = Arc::clone(&plane.ebpf);
        let _backend = backend.write().await;
        let (result, response) = oneshot::channel();
        let mut replacement = old.as_ref().clone();
        replacement.global.dial_mode = "domain".into();
        assert_eq!(
            handle_command(
                &mut plane,
                ControlCommand::ReloadConfig {
                    request_id: 7,
                    config: Box::new(replacement),
                    diagnostics: Vec::new(),
                    #[cfg(feature = "native-api")]
                    sources: None,
                    #[cfg(feature = "native-api")]
                    expected_group_revision: None,
                    result,
                }
            )
            .await,
            CommandAction::Continue
        );
        let reply = response.await.unwrap();
        assert_eq!(reply.outcome, ReloadOutcome::Rejected);
        assert!(reply.authorized.is_empty());
        let (result, response) = oneshot::channel();
        assert_eq!(
            handle_command(
                &mut plane,
                ControlCommand::MergeSubscription {
                    subscription_id,
                    revision: 1,
                    nodes: Vec::new(),
                    diagnostics: Vec::new(),
                    result,
                }
            )
            .await,
            CommandAction::Continue
        );
        let reply = response.await.unwrap();
        assert_eq!(reply.outcome, ReloadOutcome::Rejected);
        assert_eq!(reply.node_count, 1);
        assert_eq!(reply.rejection, Some("packet_endpoint_unsupported"));
        assert!(Arc::ptr_eq(&old, &*plane.config.read().await));
        let client = plane.control_client();
        let mut receiver = plane.command_rx.take().unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(
            handle_command(&mut plane, receiver.recv().await.unwrap()).await,
            CommandAction::Shutdown
        );
        tokio::time::timeout(Duration::from_secs(2), shutdown(&mut plane, None, None))
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(feature = "clash-api")]
    #[tokio::test]
    async fn selector_client_resolves_and_mode_client_rejects_without_kernel_owner() {
        use crate::control::client::{ControlError, SelectionRequest};
        let mut config = config();
        config.ensure_builtin_nodes();
        config.groups.push(Group {
            name: "packet".into(),
            nodes: vec![
                honk_config::config::DIRECT_NODE_ID,
                honk_config::config::BLOCK_NODE_ID,
            ],
            ..Default::default()
        });
        let mut plane = control_plane(config);
        let client = plane.control_client();
        let mut receiver = plane.command_rx.take().unwrap();
        let backend = Arc::clone(&plane.ebpf);
        let _backend = backend.write().await;
        let requests = async {
            assert!(
                client
                    .select(SelectionRequest::Name {
                        group: "packet".into(),
                        member: "block".into(),
                    })
                    .await
                    .is_ok()
            );
            assert!(matches!(
                client
                    .select(SelectionRequest::Name {
                        group: "missing".into(),
                        member: "block".into(),
                    })
                    .await,
                Err(ControlError::NotFound)
            ));
            #[cfg(feature = "native-api")]
            assert!(matches!(
                client
                    .mode(crate::control::client::ModeRequest::ClashMode(
                        "direct".into(),
                    ))
                    .await,
                Err(ControlError::Unsupported)
            ));
            client.shutdown().await.unwrap();
        };
        let serving = async {
            while let Some(command) = receiver.recv().await {
                if handle_command(&mut plane, command).await == CommandAction::Shutdown {
                    return;
                }
            }
            panic!("client shutdown command was not consumed");
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(requests, serving);
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), shutdown(&mut plane, None, None))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn health_network_recovery_runs_real_probes_and_joins_without_kernel_writes() {
        use honk_outbound::alive::{IpVersion, ProbeDomain};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = config();
        config.ensure_builtin_nodes();
        config.global.check_interval_secs = 3600;
        config.groups.push(Group {
            name: "packet".into(),
            nodes: vec![honk_config::config::DIRECT_NODE_ID],
            ..Default::default()
        });
        let mut plane = control_plane(config);
        plane
            .alive_set
            .set_direct_check_addr(listener.local_addr().unwrap().to_string());
        plane.alive_set.enable_health_history();
        let alive = Arc::clone(&plane.alive_set);
        let backend = Arc::clone(&plane.ebpf);
        let _backend = backend.write().await;
        let mut maintenance = tokio::time::timeout(Duration::from_secs(2), start(&mut plane))
            .await
            .unwrap();
        assert_eq!(
            handle_command(&mut plane, ControlCommand::NetworkChanged).await,
            CommandAction::Continue
        );
        let _accepted = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !alive
                .get_probe_history(
                    honk_config::config::DIRECT_NODE_ID,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                )
                .iter()
                .any(|record| record.success && record.latency.is_some())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        maintenance.abort_and_join().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), shutdown(&mut plane, None, None))
            .await
            .unwrap()
            .unwrap();
        assert!(plane.health_task.is_none());
        assert!(alive.acquire_health_probe().is_err());
        assert!(plane.runtime_registry.read().is_shutdown());
        assert!(plane.dns_controller.try_admit_query(false).is_err());
    }

    #[tokio::test]
    async fn expiry_janitors_advance_sniffers_udp_and_connection_pools_without_kernel_writes() {
        use crate::control::packet_sniffer::{PacketSnifferKey, QuicSniffOutcome};
        use crate::control::udp_endpoint::{EndpointReservation, UdpEndpoint};
        let mut plane = control_plane(config());
        let backend = Arc::clone(&plane.ebpf);
        let _backend = backend.write().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        assert!(plane.connection_pool.deposit_tcp("expired", tcp).await);
        drop(peer);
        let scope = honk_datapath::ScopeId::allocate().unwrap();
        let client = "192.0.2.1:40000".parse().unwrap();
        let target = "192.0.2.2:443".parse().unwrap();
        let key = PacketSnifferKey::new(scope, client, target);
        assert_eq!(
            plane.sniffer_pool.feed_quic_initial(
                key,
                &crate::control::quic::test_utils::rfc9001_client_initial()
            ),
            QuicSniffOutcome::Domain("example.com".into())
        );
        plane.sniffer_pool.expire_for_test();
        plane.tcp_sniff_neg_cache.note_sniff_failure(
            (target, 2),
            std::time::Instant::now() - Duration::from_secs(601),
        );
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let transport = Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            socket, target,
        ));
        let endpoint = Arc::new(UdpEndpoint::new(transport, target, uuid::Uuid::new_v4()));
        let slot = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        let EndpointReservation::Initializing(mut lease) = plane.udp_pool.reserve_or_enqueue_at(
            scope,
            client,
            target,
            b"queued",
            None,
            crate::ebpf::UdpFlowOwner::packet(),
            plane.udp_pool.initialization_epoch(),
            slot,
            crate::control::udp_endpoint::queue_now(),
            &plane.stats,
        ) else {
            panic!("UDP initializer was not admitted")
        };
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        drop(lease);
        endpoint.release();
        endpoint.expire_for_test();
        assert!(plane.udp_pool.get(scope, client, target).is_some());
        assert_eq!(plane.connection_pool.ready_metrics().entries, 1);
        assert_eq!(plane.tcp_sniff_neg_cache.len(), 1);
        tokio::time::pause();
        let mut maintenance = start(&mut plane).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert!(plane.udp_pool.get(scope, client, target).is_none());
        assert_eq!(plane.connection_pool.ready_metrics().entries, 0);
        assert!(plane.tcp_sniff_neg_cache.is_empty());
        assert_eq!(
            plane.sniffer_pool.feed_quic_initial(key, b"not QUIC"),
            QuicSniffOutcome::NotQuic
        );
        maintenance.abort_and_join().await.unwrap();
        shutdown(&mut plane, None, None).await.unwrap();
    }
}
