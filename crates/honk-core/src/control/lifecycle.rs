use super::runtime::{
    CriticalTaskExit, OutboundHealthPublisher, accept_tcp_with_admission, run_tcp_admission_scaler,
};
use super::udp_ingress::{UdpLoopState, udp_listener_loop};
use super::*;
use std::collections::HashSet;
#[cfg(test)]
use std::sync::atomic::Ordering;
use tokio::sync::watch;
use tokio::task::JoinSet;

mod tc;
mod teardown;

/// Bound for shutdown stages that have no natural deadline (watcher join,
/// runtime-generation retirement, DNS controller/persistence close). The
/// datapath hooks are already detached by then, so a hung stage must time
/// out and log rather than leave the process half-torn-down forever.
pub(super) const STAGE_TIMEOUT: Duration = Duration::from_secs(10);

struct BoundListeners {
    tcp4: tokio::io::unix::AsyncFd<std::net::TcpListener>,
    tcp6: Option<tokio::io::unix::AsyncFd<std::net::TcpListener>>,
    udp4: Vec<Arc<UdpSocket>>,
    udp6: Vec<Arc<UdpSocket>>,
    dns: Option<dns_listener::BoundDnsListener>,
    nfqueue_enabled: bool,
}

pub(super) struct RuntimeEpoch {
    listeners: BoundListeners,
    stop: watch::Sender<bool>,
    ingress: JoinSet<()>,
    tcp: JoinSet<()>,
    maintenance: OwnedTasks,
    dns: Option<dns_listener::DnsListener>,
    janitor: Option<tokio::task::JoinHandle<()>>,
    removals: Option<retirement_worker::RetirementWorker>,
    removal_errors: mpsc::UnboundedReceiver<anyhow::Error>,
    critical_errors: mpsc::UnboundedReceiver<anyhow::Error>,
    health_updates: Option<HealthUpdates>,
    #[cfg(feature = "legacy-tc")]
    queue: Option<NfqueueRuntime>,
}

type HealthUpdateKey = (Option<uuid::Uuid>, Option<(u32, u32)>);

struct HealthUpdates {
    pending: Arc<parking_lot::Mutex<Option<HashSet<HealthUpdateKey>>>>,
    wake: Arc<tokio::sync::Notify>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl HealthUpdates {
    fn start(plane: &ControlPlane) -> Self {
        let pending = Arc::new(parking_lot::Mutex::new(Some(HashSet::new())));
        let wake = Arc::new(tokio::sync::Notify::new());
        let callback_pending = Arc::clone(&pending);
        let callback_wake = Arc::clone(&wake);
        let enqueue = move |key| {
            let mut pending = callback_pending.lock();
            if let Some(pending) = pending.as_mut() {
                pending.insert(key);
                callback_wake.notify_one();
            }
        };
        plane.alive_set.set_connectivity_callback({
            let enqueue = enqueue.clone();
            // The current manager resolves dependencies at delivery. A manager-only
            // rebuild can change them without updating the committed slot index.
            move |node| enqueue((node, None))
        });
        plane.alive_set.set_routed_udp_connectivity_callback({
            let enqueue = enqueue.clone();
            // Routed evidence has no numeric slot hint. Share the raw event key so
            // a concurrent update of the same node and slot can coalesce.
            move |node, domain, family| enqueue((Some(node), Some((domain as u32, family as u32))))
        });
        plane
            .alive_set
            .set_ebpf_callback(Box::new(move |node, _, domain, family, _| {
                enqueue((Some(node), Some((domain, family))));
            }));
        let publisher = Arc::new(OutboundHealthPublisher::new(
            plane.ebpf.clone(),
            plane.config.clone(),
            plane.active_routing_plan.clone(),
            plane.group_manager.clone(),
            plane.alive_set.clone(),
        ));
        let task_pending = Arc::clone(&pending);
        let task_wake = Arc::clone(&wake);
        let task = tokio::spawn(async move {
            loop {
                task_wake.notified().await;
                let updates = {
                    let mut pending = task_pending.lock();
                    let Some(pending) = pending.as_mut() else {
                        return;
                    };
                    std::mem::take(pending)
                };
                for (node, raw_slot) in updates {
                    if task_pending.lock().is_none() {
                        return;
                    }
                    Arc::clone(&publisher).publish(node, raw_slot).await;
                }
            }
        });
        Self {
            pending,
            wake,
            task: Some(task),
        }
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        self.pending.lock().take();
        self.wake.notify_one();
        joined(&mut self.task).await
    }
}

impl ControlPlane {
    pub(in crate::control) async fn configure_health_loop(&mut self) {
        let alive_set = self.alive_set.clone();
        let interval_secs = {
            let c = self.config.read().await;
            c.global.check_interval_secs
        };
        let check_timeout = std::time::Duration::from_secs(5);

        {
            let c = self.config.read().await;
            honk_outbound::tls::set_tls_mode(&c.global.tls_implementation);
            honk_outbound::tls::set_utls_imitate(&c.global.utls_imitate);
        }

        // Configure HTTP-based health checks from config (Go: TcpCheckOption).
        {
            let c = self.config.read().await;
            let check_url = c.global.tcp_check_url.first().cloned().unwrap_or_default();
            let check_method = if c.global.tcp_check_http_method.is_empty() {
                "HEAD".to_string()
            } else {
                c.global.tcp_check_http_method.clone()
            };
            let service = self.dns_controller.dns_service();
            let recovery_resolver: crate::outbound::ResolveHook = Arc::new(move |host, port| {
                let service = service.clone();
                Box::pin(async move {
                    let resolved = service.resolve_name_without_fallback(&host).await?;
                    Ok(resolved
                        .ipv4
                        .into_iter()
                        .chain(resolved.ipv6)
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect())
                })
            });
            let prober = Arc::new(
                super::probers::http::ProxyHttpProber::new(
                    self.config.clone(),
                    self.proxy_registry.clone(),
                    self.runtime_registry.clone(),
                    check_method.clone(),
                    self.group_manager.clone(),
                )
                .with_udp_recovery_resolver(recovery_resolver),
            );
            alive_set.set_route_http_probe(prober.clone());
            if !check_url.is_empty() {
                alive_set
                    .set_http_probe(prober, check_url, check_method)
                    .await;
            } else {
                info!(
                    "HTTP health check disabled (no tcp_check_url configured), using TCP connect"
                );
            }
        }

        // Configure UDP health checks (Go: UdpCheckOption): each probe
        // cycle sends one DNS query through the node's own UDP data
        // path, so nodes with working TCP but broken UDP (e.g. an
        // AnyTLS server without UoT) are marked dead for the UDP
        // domains and excluded from UDP selection.
        {
            let dns_raw = {
                let c = self.config.read().await;
                c.global.effective_udp_check_dns().to_vec()
            };
            let quic_url = super::probers::quic_probe_url(&*self.config.read().await);
            let resolver: crate::outbound::ResolveHook = {
                let service = self.dns_controller.dns_service();
                Arc::new(move |host: String, port: u16| {
                    let service = service.clone();
                    Box::pin(async move {
                        service.resolve_name(&host).await.map(|addresses| {
                            addresses
                                .ipv4
                                .into_iter()
                                .chain(addresses.ipv6)
                                .map(|ip| std::net::SocketAddr::new(ip, port))
                                .collect()
                        })
                    })
                })
            };
            let dns_probe = UdpDnsProbeTarget::new(dns_raw, Some(resolver.clone()));
            match tokio::time::timeout(check_timeout, dns_probe.resolve()).await {
                Ok(Ok((target, _))) => info!("UDP health check enabled (dns={})", target),
                _ => info!("UDP DNS health target initialization deferred to later health checks"),
            }
            self.quic_score_target = quic_url.map(|url| {
                Arc::new(QuicScoreProbeTarget::new(
                    url,
                    Some(resolver),
                    Arc::clone(&self.degradations),
                ))
            });
            alive_set.set_udp_probe(Arc::new(ProxyUdpProber::new(
                self.config.clone(),
                self.proxy_registry.clone(),
                self.runtime_registry.clone(),
                self.stats.clone(),
                dns_probe,
                self.quic_score_target.clone(),
                self.group_manager.clone(),
            )));
        }

        info!(
            "Starting health check loop (interval={}s, timeout={}s)",
            interval_secs,
            check_timeout.as_secs()
        );
        let period = Duration::from_secs(interval_secs);
        self.health_task = Some(alive_set.spawn_health_check_loop(period, check_timeout));
    }

    async fn start_epoch_maintenance(&self, epoch: &mut RuntimeEpoch) {
        epoch.maintenance = self.start_userspace_maintenance().await;
    }

    pub(in crate::control) async fn start_userspace_maintenance(&self) -> OwnedTasks {
        let mut maintenance = OwnedTasks::default();
        let registry = self.runtime_registry.clone();
        let dns = self.dns_controller.runtime_provider();
        let groups = self.group_manager.clone();
        let tasks = &mut maintenance.0;
        tasks.push(self.udp_pool.spawn_janitor());
        tasks.push(self.sniffer_pool.spawn_janitor());
        tasks.push(super::tcp_sniff::spawn_sniff_neg_cache_janitor(
            self.tcp_sniff_neg_cache.clone(),
        ));
        tasks.push(self.connection_pool.spawn_janitor());
        tasks.push(tokio::spawn(run_tcp_admission_scaler(
            self.concurrency_limit.clone(),
            self.resource_budget,
            self.stats.clone(),
            self.tcp_admission_target.clone(),
        )));
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(honk_outbound::runtime::REAP_INTERVAL);
            tick.tick().await;
            loop {
                tick.tick().await;
                registry.read().reap_idle_resources();
                dns.current().reap_idle_resources();
            }
        }));
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let manager = groups.read().clone();
                manager.observe_transport_quality();
            }
        }));
        self.start_preconnect().await;
        let generation = self.runtime_registry.read().clone();
        self.start_udp_warm_coordinator(generation.clone()).await;
        self.start_selector_warm_coordinator(generation).await;
        maintenance
    }
}

async fn cleanup_stage<T>(future: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    tokio::time::timeout(STAGE_TIMEOUT, future)
        .await
        .map_err(|_| anyhow::anyhow!("runtime cleanup exceeded its stop deadline"))?
}

pub(super) async fn joined(task: &mut Option<tokio::task::JoinHandle<()>>) -> anyhow::Result<()> {
    let Some(handle) = task.as_mut() else {
        return Ok(());
    };
    let result = match tokio::time::timeout(STAGE_TIMEOUT, &mut *handle).await {
        Ok(result) => result.map_err(anyhow::Error::from),
        Err(_) => {
            handle.abort();
            Err(anyhow::anyhow!(
                "owned runtime task exceeded its stop deadline"
            ))
        }
    };
    task.take();
    result
}

async fn join_retirement_owner<T: Default>(
    task: &mut Option<tokio::task::JoinHandle<T>>,
    owner: &'static str,
) -> anyhow::Result<T> {
    let Some(handle) = task.as_mut() else {
        return Ok(T::default());
    };
    let result = match tokio::time::timeout(STAGE_TIMEOUT, &mut *handle).await {
        Ok(result) => result,
        Err(_) => {
            warn!(
                owner,
                "Retirement owner exceeded its stop deadline; waiting for admitted cleanup"
            );
            handle.await
        }
    };
    task.take();
    result.map_err(anyhow::Error::from)
}

async fn abort_and_join(task: &mut Option<tokio::task::JoinHandle<()>>) -> anyhow::Result<()> {
    if let Some(handle) = task.as_ref() {
        handle.abort();
    }
    match joined(task).await {
        Err(error)
            if error
                .downcast_ref::<tokio::task::JoinError>()
                .is_some_and(tokio::task::JoinError::is_cancelled) =>
        {
            Ok(())
        }
        result => result,
    }
}

/// Background tasks that are aborted when dropped.
#[derive(Default)]
pub(super) struct OwnedTasks(pub(super) Vec<tokio::task::JoinHandle<()>>);

impl OwnedTasks {
    /// Aborts every task, then joins each; cancellation is the expected exit.
    pub(super) async fn abort_and_join(&mut self) -> anyhow::Result<()> {
        for task in &self.0 {
            task.abort();
        }
        let mut error = None;
        for task in self.0.drain(..) {
            retain_error(&mut error, abort_and_join(&mut Some(task)).await);
        }
        error.map_or(Ok(()), Err)
    }
}

impl Drop for OwnedTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

pub(in crate::control) fn retain_error(
    target: &mut Option<anyhow::Error>,
    result: anyhow::Result<()>,
) {
    if let Err(error) = result {
        target.get_or_insert(error);
    }
}

enum EpochEvent {
    Command(Option<ControlCommand>),
    Accepted(
        io::Result<(
            TcpStream,
            SocketAddr,
            &'static str,
            tokio::sync::OwnedSemaphorePermit,
        )>,
    ),
    Fatal(anyhow::Error),
    #[cfg(feature = "legacy-tc")]
    TokenExhausted,
    Reaped,
}

impl RuntimeEpoch {
    async fn next(
        &mut self,
        plane: &ControlPlane,
        commands: &mut mpsc::Receiver<ControlCommand>,
    ) -> EpochEvent {
        tokio::select! {
            biased;
            error = self.removal_errors.recv() => EpochEvent::Fatal(error.unwrap_or_else(|| anyhow::anyhow!("UDP removal owner stopped"))),
            error = self.critical_errors.recv() => EpochEvent::Fatal(error.unwrap_or_else(|| anyhow::anyhow!("critical runtime owner stopped"))),
            event = async {
                #[cfg(feature = "legacy-tc")]
                { match wait_nfqueue_event(&mut self.queue, &plane.ebpf).await {
                    NfqueueRuntimeEvent::Fatal(error) => EpochEvent::Fatal(error),
                    NfqueueRuntimeEvent::TokenExhausted => EpochEvent::TokenExhausted,
                } }
                #[cfg(not(feature = "legacy-tc"))]
                { std::future::pending::<EpochEvent>().await }
            } => event,
            command = commands.recv() => EpochEvent::Command(command),
            result = self.tcp.join_next(), if !self.tcp.is_empty() => reap_tcp(result),
            result = accept_tcp_with_admission(&self.listeners.tcp4, self.listeners.tcp6.as_ref(), plane.concurrency_limit.clone(), plane.stats.clone()), if !plane.drain_tracker.should_reject() => EpochEvent::Accepted(result),
        }
    }
}

/// A connection task owns one flow; its panic must end that flow only,
/// never the runtime epoch.
fn reap_tcp(result: Option<Result<(), tokio::task::JoinError>>) -> EpochEvent {
    if let Some(Err(error)) = result
        && !error.is_cancelled()
    {
        error!(%error, "TCP connection task panicked");
    }
    EpochEvent::Reaped
}

impl ControlPlane {
    async fn fence_runtime(&self) -> anyhow::Result<()> {
        let mut error = None;
        if let Some(flags) = self.datapath_flags.as_ref() {
            retain_error(&mut error, flags.fence_nfqueue().await);
        }
        retain_error(
            &mut error,
            self.ebpf.write().await.set_datapath_ready(false),
        );
        self.drain_tracker.start_rejecting();
        error.map_or(Ok(()), Err)
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut commands = self
            .command_rx
            .take()
            .expect("control command receiver already taken");
        let mut authorizations = crate::subscription::SubscriptionAuthorizations::new(
            &self.config.read().await.subscriptions,
        )?;
        let mut epoch = None;
        let startup = async {
            let listeners = self.bind_runtime_listeners().await?;
            epoch = Some(self.prepare_epoch(listeners).await?);
            self.configure_health_loop().await;
            self.open_epoch(epoch.as_mut().expect("startup epoch"))
                .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let mut fatal = startup.err();
        if fatal.is_none() {
            let active = epoch.as_mut().expect("startup epoch");
            self.start_epoch_maintenance(active).await;
            #[cfg(feature = "native-api")]
            self.publish_phase(EnginePhase::Running);
            #[cfg(target_os = "linux")]
            if let Err(error) =
                libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready])
            {
                warn!(%error, "sd_notify readiness failed");
            }
            // A persistent accept error repeats every iteration; warn once per episode.
            let mut accept_failing = false;
            while fatal.is_none() && !self.shutdown_requested.requested() {
                match active.next(self, &mut commands).await {
                    EpochEvent::Command(command) => {
                        let Some(command) = command else {
                            break;
                        };
                        let drain = self.drain_tracker.clone();
                        if !self
                            .dispatch_control_command(command, &drain, &mut authorizations)
                            .await
                        {
                            break;
                        }
                    }
                    EpochEvent::Fatal(error) => fatal = Some(error),
                    #[cfg(feature = "legacy-tc")]
                    EpochEvent::TokenExhausted => {
                        if let Some(queue) = active.queue.as_mut()
                            && let Err(error) = self.recover_nfqueue_token_exhaustion(queue).await
                        {
                            fatal = Some(error);
                        }
                    }
                    EpochEvent::Reaped => {}
                    EpochEvent::Accepted(Ok((stream, address, family, permit))) => {
                        if std::mem::replace(&mut accept_failing, false) {
                            info!("TPROXY TCP accept recovered");
                        }
                        if self.drain_tracker.should_reject() {
                            continue;
                        }
                        if let Err(error) = set_so_mark_zero(&stream) {
                            warn!(%error, "failed to clear accepted socket bypass mark");
                        }
                        let handle = self.spawn_handle();
                        let guard = ConnectionGuard::new(self.drain_tracker.clone());
                        let flow = self.stats.track_tcp_flow();
                        active.tcp.spawn(async move {
                            let (_permit, _guard, _flow) = (permit, guard, flow);
                            if let Err(error) = handle.serve_connection(stream, address).await {
                                debug!(%error, family, "TCP connection ended");
                            }
                        });
                    }
                    EpochEvent::Accepted(Err(error)) => {
                        crate::logging::warn_on_entry!(
                            !std::mem::replace(&mut accept_failing, true),
                            %error,
                            "TPROXY TCP accept failed"
                        );
                        if error.raw_os_error() == Some(libc::EMFILE) {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
        self.shutdown_runtime(epoch.as_mut(), fatal).await
    }
}

#[cfg(all(test, feature = "native-api"))]
mod tests;

#[cfg(test)]
#[tokio::test]
async fn nested_exit_failures_and_selector_changes_republish_effective_slots() -> anyhow::Result<()>
{
    use crate::control::tests::support::{canonical_socks5, control_plane};
    use honk_outbound::group::{ScoreSelectionContext, SelectionNetwork, SelectorNetworks, Target};
    use honk_outbound::proxy::{DialFailureScope, DialRef, dial_failure_scope};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let first = canonical_socks5("first", "127.0.0.1", listener.local_addr()?.port(), None);
    let other = canonical_socks5("other", "127.0.0.1", 11081, None);
    let near = canonical_socks5("near", "127.0.0.1", 11082, None);
    let far = canonical_socks5("far", "127.0.0.1", 11083, None);
    let spare = canonical_socks5("spare", "127.0.0.1", 11084, None);
    let mut config = Config {
        nodes: vec![
            first.clone(),
            other.clone(),
            near.clone(),
            far.clone(),
            spare.clone(),
        ],
        groups: vec![
            Group {
                name: "root".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![spare.id],
                groups: vec!["middle".into(), "deny".into()],
                default: Some("middle".into()),
                ..Default::default()
            },
            Group {
                name: "middle".into(),
                policy: GroupPolicy::Score,
                groups: vec!["choices".into()],
                exit: Some("far".into()),
                ..Default::default()
            },
            Group {
                name: "choices".into(),
                policy: GroupPolicy::URLTest,
                nodes: vec![first.id, other.id],
                exit: Some("near".into()),
                ..Default::default()
            },
            Group {
                name: "deny".into(),
                exit: Some("near".into()),
                final_outbound: Some("block".into()),
                ..Default::default()
            },
            Group {
                name: "via-final".into(),
                final_outbound: Some("middle".into()),
                ..Default::default()
            },
            Group {
                name: "first-only".into(),
                nodes: vec![first.id],
                exit: Some("near".into()),
                ..Default::default()
            },
            Group {
                name: "gated".into(),
                exit: Some("far".into()),
                final_outbound: Some("first-only".into()),
                ..Default::default()
            },
            Group {
                name: "fallback".into(),
                policy: GroupPolicy::Score,
                groups: vec!["choices".into()],
                exit: Some("far".into()),
                final_outbound: Some("block".into()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    config.global.nfqueue_enable = false;
    config.ensure_builtin_nodes();
    let cp = control_plane(config);
    for family in [IpVersion::V4, IpVersion::V6] {
        cp.alive_set
            .report_unavailable_forced(spare.id, ProbeDomain::Tcp, family);
    }
    let mut updates = HealthUpdates::start(&cp);
    let manager = cp.group_manager.read().clone();
    let generation = cp.runtime_registry.read().clone();
    let root = OutboundIndex::UserBase as u8;
    let slot = async |index, domain, family, expected| -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if cp
                    .ebpf
                    .read()
                    .await
                    .get_outbound_alive(index, domain, family)?
                    == expected
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?
    };
    assert!(!cp.alive_set.is_registered(near.id) && !cp.alive_set.is_registered(far.id));
    slot(root, 0, 0, true).await?;
    slot(root + 6, 0, 0, true).await?;
    slot(root, 2, 0, false).await?;
    assert_eq!(
        manager.score_budget_counters("middle", SelectionNetwork::Tcp),
        Default::default(),
    );
    let family = IpVersion::V4;
    cp.alive_set
        .record_probe_latency(first.id, ProbeDomain::Tcp, family, Duration::from_millis(1));
    cp.alive_set.record_probe_latency(
        other.id,
        ProbeDomain::Tcp,
        family,
        Duration::from_millis(500),
    );
    let context = ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, family);
    let plan = |name| manager.dial_plan_for_target(name, &context, None);
    let entries = |name| plan(name).0.entries;
    let (primary, revision) = plan("root");
    let entry = primary.entries.into_iter().next().unwrap();
    let target = manager.own_target(Target {
        node: entry.node,
        route: entry.route,
    });
    let route = target.route().unwrap();
    assert_eq!(route.hops(), [first.id, near.id, far.id]);
    let server = tokio::spawn(async move {
        for _ in 0..10 {
            let (mut stream, _) = listener.accept().await.unwrap();
            for (port, status) in [(11082u16, 0u8), (11083, 5)] {
                let mut greeting = [0; 2];
                stream.read_exact(&mut greeting).await.unwrap();
                let mut methods = vec![0; usize::from(greeting[1])];
                stream.read_exact(&mut methods).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..4], &[5, 1, 0, 1]);
                assert_eq!(&request[8..], &port.to_be_bytes());
                stream
                    .write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            }
        }
    });
    for _ in 0..10 {
        let stamp = revision.admit();
        let err = cp
            .proxy_registry
            .dial_ref(
                Arc::clone(&generation),
                DialRef::Route(route),
                "127.0.0.1:9".parse()?,
                None,
                Duration::from_secs(2),
            )
            .await
            .expect_err("middle SOCKS hop refuses its next hop");
        assert_eq!(
            dial_failure_scope(err.as_ref()),
            DialFailureScope::Prefix(2)
        );
        manager.report_route_failure("root", &target, family, stamp, err.as_ref());
    }
    server.await?;
    for name in ["root", "via-final"] {
        assert_eq!(
            entries(name)[0].route.as_deref().unwrap().hops(),
            [other.id, near.id, far.id]
        );
    }
    assert_eq!(
        entries("choices")[0].route.as_deref().unwrap().hops(),
        [first.id, near.id]
    );
    assert!(entries("gated").is_empty());
    slot(root + 6, 0, 0, false).await?;
    slot(root + 6, 0, 1, true).await?;
    assert!(
        [first.id, near.id, far.id]
            .into_iter()
            .all(|id| cp.alive_set.is_alive_for(id, ProbeDomain::Tcp, family))
    );

    for _ in 0..10 {
        cp.alive_set
            .report_unavailable_traffic(far.id, ProbeDomain::Tcp, IpVersion::V6);
    }
    let v6_context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V6);
    for name in ["root", "fallback"] {
        let (v6, _) = manager.dial_plan_for_target(name, &v6_context, None);
        assert_eq!(v6.health_family, family);
        assert_eq!(v6.entries[0].node.id, other.id);
    }
    for _ in 0..10 {
        cp.alive_set
            .report_unavailable_traffic(far.id, ProbeDomain::Tcp, family);
    }
    assert!(entries("root").is_empty() && entries("via-final").is_empty());
    assert_eq!(entries("fallback")[0].node.protocol(), NodeProtocol::Block);
    slot(root, 0, 0, false).await?;
    slot(root, 0, 1, false).await?;
    slot(root + 4, 0, 0, false).await?;
    cp.alive_set
        .report_available_traffic(far.id, ProbeDomain::Tcp, family);
    slot(root, 0, 1, true).await?;
    manager.set_selector_choice("root", "deny", SelectorNetworks::Both)?;
    assert_eq!(
        manager
            .select_node_for_domain("root", ProbeDomain::DataUdp, family)
            .unwrap()
            .protocol(),
        NodeProtocol::Block,
    );
    slot(root, 2, 0, true).await?;
    manager.set_selector_choice("root", "middle", SelectorNetworks::Both)?;
    slot(root, 2, 0, false).await?;

    slot(root, 0, 0, true).await?;
    manager.set_selector_choice("root", "spare", SelectorNetworks::Both)?;
    slot(root, 0, 0, false).await?;
    assert!(
        manager
            .select_node_for_domain("root", ProbeDomain::DataUdp, family)
            .is_none()
    );
    cp.alive_set.record_probe_latency(
        spare.id,
        ProbeDomain::DnsUdp,
        IpVersion::V6,
        Duration::from_millis(1),
    );
    slot(root, 2, 0, true).await?;
    let provider = cp.dns_controller.runtime_provider();
    let before = provider.current_generation();
    let mut successor = (**cp.config.read().await).clone();
    successor.groups[6].name = "gated-successor".into();
    assert!(
        cp.reload_runtime_config(successor, Default::default())
            .await
    );
    assert_ne!(provider.current_generation(), before);
    assert!(
        cp.group_manager
            .read()
            .dial_plan_for_target("gated-successor", &context, None)
            .0
            .entries
            .is_empty()
    );
    slot(root + 6, 0, 0, false).await?;
    updates.stop().await
}

#[cfg(test)]
#[tokio::test]
async fn orphaned_udp_hop_republishes_committed_slot_after_manager_rebind() -> anyhow::Result<()> {
    use crate::control::tests::support::{canonical_socks5, control_plane};
    use crate::test_support::routed_udp::{
        PASSWORD, Peer, dns_reply, front as serve_front, trojan_peer,
    };
    use honk_outbound::alive::{ProbeCancellation, RouteHttpProber};
    use honk_outbound::group::{DialKey, ScoreSelectionContext, SelectionNetwork};
    use honk_outbound::proxy::{ChainHopFailure, NodeFailure};

    let entry = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let exit = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = UdpSocket::bind("127.0.0.1:0").await?;
    let dns = origin.local_addr()?;
    let exit_addr = exit.local_addr()?;
    let front = canonical_socks5("front", "127.0.0.1", entry.local_addr()?.port(), None);
    let mut land = Node::from_share_link(&format!("trojan://{PASSWORD}@{exit_addr}#land"))?;
    land.tls_mut().unwrap().enabled = false;
    land.id = land.derive_id();
    let chain = Node::chain_from_nodes("via", &[&front, &land])?;
    let land_id = land.id;
    let chain_id = chain.id;
    let chain_key = DialKey::Node(chain_id);
    let mut config = Config {
        groups: vec![
            Group {
                name: "chosen".into(),
                nodes: vec![front.id],
                ..Default::default()
            },
            Group {
                name: "unrelated".into(),
                nodes: vec![front.id],
                ..Default::default()
            },
        ],
        nodes: vec![front, land, chain],
        ..Default::default()
    };
    config.global.nfqueue_enable = false;
    config.global.udp_check_dns = Some(vec![dns.to_string()]);
    config.ensure_builtin_nodes();
    let cp = control_plane(config.clone());
    let compiled = cp.active_routing_plan.read().plan.clone();
    assert_eq!(compiled.group_slots[0].1, "chosen");
    let baseline = group_connectivity_snapshot(&config, &cp.group_manager.read(), &cp.alive_set);
    publish_group_connectivity(cp.ebpf.write().await.as_mut(), &baseline)?;
    assert!(!cp.outbound_id_map.read().contains_key(&land_id));
    let mut updates = HealthUpdates::start(&cp);

    config.groups[0].nodes[0] = chain_id;
    config.groups.swap(0, 1);
    *cp.config.write().await = Arc::new(config);
    cp.reload_group_manager().await?;
    assert!(Arc::ptr_eq(&cp.active_routing_plan.read().plan, &compiled));
    assert!(!cp.outbound_id_map.read().contains_key(&land_id));
    assert!(!cp.alive_set.is_registered(land_id));

    let base = OutboundIndex::UserBase as u8;
    let domain = ProbeDomain::DataUdp;
    let family = IpVersion::V4;
    let wait_slot = async |expected| -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let backend = cp.ebpf.read().await;
                if backend.get_outbound_alive(base, domain as u32, family as u32)? == expected {
                    assert!(backend.get_outbound_alive(base + 1, domain as u32, family as u32)?);
                    assert!(backend.get_outbound_alive(
                        base,
                        domain as u32,
                        IpVersion::V6 as u32
                    )?);
                    assert!(backend.get_outbound_alive(
                        base,
                        ProbeDomain::Tcp as u32,
                        family as u32
                    )?);
                    return Ok(());
                }
                drop(backend);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?
    };
    wait_slot(true).await?;
    let manager = cp.group_manager.read().clone();
    let config = cp.config.read().await.clone();
    let context = ScoreSelectionContext::aggregate(SelectionNetwork::Udp, domain, family);
    let plan = || {
        resolve_outbound_plan_for_target(
            &config,
            &manager,
            "chosen",
            &context,
            OutboundConstraint::Any,
        )
    };
    let fault = ChainHopFailure {
        hop: 1,
        node: land_id,
        error: NodeFailure(anyhow::anyhow!("invalid terminal packet record")).into(),
    };
    for _ in 0..50 {
        let plan = plan();
        let [target] = plan.targets.as_slice() else {
            panic!("UDP chain unavailable before the threshold");
        };
        assert_eq!(target.key(), chain_key);
        let attempt = manager
            .capture_udp_route(
                target,
                &plan.selection_chains[0],
                &plan.final_owners[0],
                plan.route_revision,
                domain,
                plan.health_family,
            )
            .expect("active chain evidence");
        assert!(manager.report_udp_route_failure(&attempt, &fault));
    }
    assert!(plan().targets.is_empty());
    wait_slot(false).await?;

    cp.ebpf
        .write()
        .await
        .inject_routing_fault(crate::ebpf::RoutingPushPhase::Root, 1)?;
    assert_eq!(
        cp.apply_runtime_config(
            config.as_ref().clone(),
            Default::default(),
            &DrainTracker::new()
        )
        .await,
        ReloadOutcome::Rejected
    );
    assert!(Arc::ptr_eq(&cp.active_routing_plan.read().plan, &compiled));
    assert!(Arc::ptr_eq(&cp.group_manager.read(), &manager));
    wait_slot(false).await?;

    let front_peer = Peer::start(entry, move |stream, _| {
        serve_front(stream, exit_addr, false)
    });
    let exit_peer = Peer::start(exit, move |stream, _| async move {
        trojan_peer(stream, &[dns], dns).await
    });
    let prober = crate::control::probers::http::ProxyHttpProber::new(
        cp.config_handle(),
        cp.proxy_registry(),
        cp.runtime_registry(),
        "HEAD".into(),
        cp.group_manager(),
    );
    let ticket = cp
        .alive_set
        .take_route_probe()
        .expect("original chain must retain its recovery ticket");
    assert_eq!(ticket.target(), chain_key);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let respond = async {
        let mut query = [0; 512];
        let (len, peer) = origin.recv_from(&mut query).await?;
        wait_slot(false).await?;
        let reply = dns_reply(&query[..len]);
        assert_eq!(origin.send_to(&reply, peer).await?, reply.len());
        anyhow::Ok(())
    };
    tokio::time::timeout_at(deadline, async {
        tokio::try_join!(
            prober.probe_route_udp(
                &cp.alive_set,
                &ticket,
                deadline,
                ProbeCancellation::default()
            ),
            respond
        )
    })
    .await??;
    assert_eq!(plan().targets[0].key(), chain_key);
    wait_slot(true).await?;
    assert!(!cp.outbound_id_map.read().contains_key(&land_id));
    front_peer.finish(1).await;
    exit_peer.finish(1).await;
    updates.stop().await
}

#[cfg(test)]
mod reap_tests {
    use super::*;

    #[tokio::test]
    async fn a_panicked_or_cancelled_connection_task_is_reaped_not_fatal() {
        let mut tasks = JoinSet::<()>::new();
        tasks.spawn(async { panic!("connection bug") });
        let panicked = tasks.join_next().await;
        assert!(matches!(&panicked, Some(Err(error)) if error.is_panic()));
        assert!(matches!(reap_tcp(panicked), EpochEvent::Reaped));

        tasks.spawn(std::future::pending::<()>());
        tasks.abort_all();
        let cancelled = tasks.join_next().await;
        assert!(matches!(&cancelled, Some(Err(error)) if error.is_cancelled()));
        assert!(matches!(reap_tcp(cancelled), EpochEvent::Reaped));
    }
}

#[cfg(test)]
mod policy_capability_tests {
    use super::*;

    #[tokio::test]
    async fn software_policy_reloads_but_cannot_start_tc_listeners() -> anyhow::Result<()> {
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        config.routing.default_outbound = "direct".into();
        config.global.nfqueue_enable = false;
        config.global.preconnect_node_count = 0;
        config.global.udp_warm_node_count = 0;
        let admission = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut plane = ControlPlane::new(
            config.clone(),
            Box::new(crate::ebpf::userspace::UserspaceBackend::new(
                Arc::clone(&admission),
                Arc::new(parking_lot::RwLock::new(
                    crate::ebpf::PnameSupport::Unavailable,
                )),
            )),
            Router::new(&[], "direct")?,
            Arc::new(ProxyRegistry::default_resolver()?),
            DnsResolver::new(&config.dns)?,
            crate::control::tests::support::test_dns_forwarder(),
        )?;
        assert!(plane.tc_kernel.is_none());
        assert!(plane.spawn_handle().tc_kernel.is_none());
        let generation = plane.ebpf.read().await.routing_policy_generation();
        let error = plane
            .bind_runtime_listeners()
            .await
            .err()
            .expect("TC capability is required before binding");
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
        config.routing.default_outbound = "block".into();
        assert!(
            plane
                .reload_runtime_config(config, Default::default())
                .await
        );
        assert!(plane.ebpf.read().await.routing_policy_generation() > generation);
        assert_eq!(plane.config.read().await.routing.default_outbound, "block");
        plane.stop_packet_epoch().await?;
        plane.finalize_shutdown().await?;
        assert!(!admission.load(Ordering::Acquire));
        Ok(())
    }
}

#[cfg(test)]
mod retirement_join_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn retirement_join_outlives_warning_and_cancelled_waiter() -> anyhow::Result<()> {
        for owner in ["flow retirement worker", "BPF janitor"] {
            let (release, waiting) = tokio::sync::oneshot::channel();
            let mut task = Some(tokio::spawn(async move { waiting.await.unwrap() }));
            let mut joining = Box::pin(join_retirement_owner(&mut task, owner));
            assert!(futures::poll!(&mut joining).is_pending());
            tokio::time::advance(STAGE_TIMEOUT + Duration::from_secs(1)).await;
            assert!(futures::poll!(&mut joining).is_pending());
            drop(joining);
            assert!(!task.as_ref().unwrap().is_finished());
            let mut joining = Box::pin(join_retirement_owner(&mut task, owner));
            assert!(futures::poll!(&mut joining).is_pending());
            release.send(()).unwrap();
            joining.await?;
            assert!(task.is_none());
        }
        Ok(())
    }
}
