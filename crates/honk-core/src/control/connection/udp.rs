use super::overall_dial_timeout;
use super::routing::{RoutingDecision, build_connection_info, connection_chains};
use crate::control::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use crate::control::udp_endpoint::{RawDnsRoute, UdpEndpoint, UdpInitLease};
use crate::control::*;
use crate::group::{SelectionNetwork, SelectionPlanMode};

enum PreparedEndpointTransport {
    Flow(honk_outbound::proxy::PreparedUdpTransport),
    #[cfg(feature = "rprx")]
    Source(crate::control::udp_endpoint::VlessSourcePreparation),
}

enum CommittedEndpointTransport {
    Flow(Arc<dyn honk_outbound::proxy::PacketTransport>),
    #[cfg(feature = "rprx")]
    Source(crate::control::udp_endpoint::SourceAttachment),
}

#[cfg(feature = "rprx")]
fn vless_source_path(node: &Node, port: u16) -> Option<honk_config::node::VlessUdpPath> {
    let path = node.vless()?.udp_path(port)?;
    matches!(
        path,
        honk_config::node::VlessUdpPath::Xudp
            | honk_config::node::VlessUdpPath::CoolShared
            | honk_config::node::VlessUdpPath::CoolSeparate
    )
    .then_some(path)
}

impl ControlPlaneHandle {
    pub(in crate::control) async fn serve_udp_connection(
        &self,
        lease: UdpInitLease,
    ) -> anyhow::Result<()> {
        #[cfg(feature = "ebpf")]
        let pending_cleanup = if lease.decision_token() == 0 {
            None
        } else {
            let verdicts = self
                .pending_udp_verdicts
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("staged UDP lease has no verdict owner"))?;
            Some((
                verdicts,
                crate::control::nfqueue::PendingUdpVerdicts::identity_for_lease(&lease),
            ))
        };
        #[cfg(not(feature = "ebpf"))]
        if lease.decision_token() != 0 {
            anyhow::bail!("staged UDP lease requires the ebpf feature");
        }
        let cancellation = lease.wait_cancellation();
        tokio::select! {
            _ = cancellation => {
                #[cfg(feature = "ebpf")]
                if let Some((verdicts, identity)) = &pending_cleanup {
                    verdicts.cancel(*identity).await?;
                }
                Ok(())
            }
            result = self.initialize_udp_connection(lease) => {
                let Err(error) = result else {
                    return Ok(());
                };
                #[cfg(feature = "ebpf")]
                if let Some((verdicts, identity)) = &pending_cleanup
                    && let Err(cancel_error) = verdicts.cancel(*identity).await
                {
                    return Err(error.context(format!(
                        "staged UDP cleanup also failed: {cancel_error}"
                    )));
                }
                Err(error)
            }
        }
    }

    async fn initialize_udp_connection(&self, mut lease: UdpInitLease) -> anyhow::Result<()> {
        let client_addr = lease.client_addr();
        let original_dst = lease.original_dst();
        let data = lease.first_payload();
        let raw_dns_route = lease.raw_dns_route();
        #[cfg(feature = "ebpf")]
        let pending = if lease.decision_token() == 0 {
            None
        } else {
            let verdicts = self
                .pending_udp_verdicts
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("staged UDP lease has no verdict owner"))?;
            Some((
                verdicts,
                crate::control::nfqueue::PendingUdpVerdicts::identity_for_lease(&lease),
            ))
        };
        #[cfg(not(feature = "ebpf"))]
        if lease.decision_token() != 0 {
            anyhow::bail!("staged UDP lease requires the ebpf feature");
        }
        debug!(
            "UDP datagram from {} -> {} ({} bytes, decision token {})",
            client_addr,
            original_dst,
            data.len(),
            lease.decision_token()
        );

        let dial_mode = if raw_dns_route.is_some() {
            anyhow::ensure!(
                original_dst.port() == 53 && lease.decision_token() == 0,
                "raw DNS ownership requires an unstaged UDP/53 lease"
            );
            DialMode::Ip
        } else {
            let config = self.config.read().await;
            config
                .global
                .dial_mode
                .parse::<DialMode>()
                .map_err(|_| anyhow::anyhow!("invalid global.dial_mode"))?
        };

        // A staged early exit must retire its held originals immediately.
        if is_honk_internal_addr(&original_dst.ip()) || is_honk_internal_addr(&client_addr.ip()) {
            trace!(
                "Skipping honk-internal UDP {} -> {}",
                client_addr, original_dst
            );
            #[cfg(feature = "ebpf")]
            if let Some((verdicts, identity)) = &pending {
                verdicts.cancel(*identity).await?;
            }
            return Ok(());
        }
        if is_broadcast_or_multicast(&original_dst.ip()) {
            trace!(
                "Skipping broadcast/multicast UDP {} -> {}",
                client_addr, original_dst
            );
            #[cfg(feature = "ebpf")]
            if let Some((verdicts, identity)) = &pending {
                verdicts.cancel(*identity).await?;
            }
            return Ok(());
        }

        let handoff = if raw_dns_route.is_some() {
            None
        } else {
            let tuples = build_tuples_key(
                original_dst.ip(),
                original_dst.port(),
                client_addr.ip(),
                client_addr.port(),
                17, // UDP
            );
            self.lookup_udp_handoff(&tuples, lease.decision_token())
                .await?
        };
        let skip_sniff = matches!(dial_mode, DialMode::Ip)
            || handoff.as_ref().is_some_and(|ho| {
                ho.must != 0
                    || matches!(
                        ho.outbound,
                        x if x == OutboundIndex::Direct as u8
                            || x == OutboundIndex::Block as u8
                            || x == OutboundIndex::MustRules as u8
                    )
            });
        let mut follower_rx = None;
        let mut sniffed_followers = Vec::new();
        let quic_domain: Option<String> = if skip_sniff {
            None
        } else {
            use crate::control::packet_sniffer::QuicSniffOutcome;
            let sniffer_key =
                crate::control::packet_sniffer::PacketSnifferKey::new(client_addr, original_dst);
            let mut outcome = self.sniffer_pool.feed_quic_initial(sniffer_key, &data);
            // A fragmented ClientHello: collect the rest of the Initial
            // flight before deciding which outbound owns the flow.
            if matches!(outcome, QuicSniffOutcome::Incomplete) {
                follower_rx = lease.take_queue_receiver();
                if let Some(rx) = follower_rx.as_mut() {
                    (outcome, sniffed_followers) =
                        self.collect_initial_fragments(sniffer_key, rx).await;
                }
            }
            if matches!(outcome, QuicSniffOutcome::Incomplete) {
                debug!(
                    "QUIC ClientHello unresolved within budget; dropping for retransmit {} -> {}",
                    client_addr, original_dst
                );
                #[cfg(feature = "ebpf")]
                if let Some((verdicts, identity)) = &pending {
                    verdicts.cancel(*identity).await?;
                }
                return Ok(());
            }
            outcome.into_domain()
        };
        let (quic_domain, domain_verified) = self
            .apply_domain_reality_check(dial_mode, quic_domain, original_dst.ip(), client_addr.ip())
            .await;

        let route_started_at = std::time::Instant::now();
        let mut route = if let Some(raw_dns_route) = raw_dns_route {
            let (outbound, mark) = match raw_dns_route {
                RawDnsRoute::Group(name) => (name.to_string(), None),
                RawDnsRoute::Direct(mark) => (
                    "direct".to_owned(),
                    honk_outbound::proxy::DirectMark::new(mark),
                ),
            };
            RoutingDecision {
                outbound,
                must: true,
                mark,
                matched_rule: None,
                reroute_by_sniffed_domain: false,
            }
        } else {
            let conn_info = build_connection_info(
                quic_domain.clone(),
                original_dst,
                client_addr,
                "udp",
                handoff.as_ref(),
            );
            self.prepare_routing(dial_mode, &conn_info, domain_verified, handoff.as_ref())
                .await
        };
        #[cfg(feature = "ebpf")]
        let reroute_by_sniffed_domain = route.reroute_by_sniffed_domain;
        let matched_rule = route.matched_rule.take();
        self.apply_mode_override(&mut route).await;
        let outbound_name = std::mem::take(&mut route.outbound);
        let target_domain = if matches!(
            outbound_name.as_str(),
            "direct" | "block" | "must_rules" | "control_plane_routing"
        ) {
            None
        } else {
            quic_domain.as_deref().map(Arc::<str>::from)
        };
        let target_is_domain = target_domain.is_some();
        let mark = route.mark;
        self.stats
            .record_udp_route_latency(route_started_at.elapsed());
        #[cfg(feature = "ebpf")]
        if let Some((verdicts, identity)) = &pending {
            match outbound_name.as_str() {
                "direct" => {
                    verdicts
                        .activate_direct(
                            *identity,
                            &mut lease,
                            mark.map_or(0, honk_outbound::proxy::DirectMark::get),
                        )
                        .await?;
                    if let Some(domain) = &quic_domain
                        && Self::should_write_sniffed_domain_bitmap(
                            handoff.as_ref(),
                            reroute_by_sniffed_domain,
                        )
                    {
                        self.push_sniffed_domain_bitmap(domain, original_dst.ip())
                            .await;
                    }
                    debug!(
                        network = "udp",
                        outbound = %outbound_name,
                        ip = %original_dst,
                        src = %client_addr,
                        sniffed = quic_domain.as_deref().unwrap_or(""),
                        ebpf_offload = true,
                        "UDP offloaded to eBPF: {} -> {}",
                        client_addr,
                        original_dst,
                    );
                    return Ok(());
                }
                "block" => {
                    verdicts.block(*identity, &mut lease).await?;
                    return Ok(());
                }
                _ => {
                    let final_outbound = self.outbound_name_to_index(&outbound_name).await;
                    verdicts
                        .activate_proxy(
                            *identity,
                            &lease,
                            final_outbound,
                            mark.map_or(0, honk_outbound::proxy::DirectMark::get),
                        )
                        .await?;
                }
            }
        }
        // This guard is created exactly once and is transferred to Ready only
        // after a real driver has reached its barrier.
        lease.set_connection_guard(self.stats.track_connection(&outbound_name));

        let requested_ipver = if original_dst.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let (plan, selection_chains) = {
            let config = self.config.read().await;
            let gm = self.group_manager.read();
            let plan = crate::control::reload::resolve_udp_outbound_plan_for_target(
                &config,
                &gm,
                &outbound_name,
                &crate::group::ScoreSelectionContext {
                    network: SelectionNetwork::Udp,
                    probe_domain: ProbeDomain::DataUdp,
                    target_family: Some(requested_ipver),
                    health_family: requested_ipver,
                    target: Some(match target_domain.as_deref() {
                        Some(domain) => {
                            crate::group::ScoreTarget::domain(domain, original_dst.port())
                        }
                        None => original_dst.into(),
                    }),
                },
            );
            let selection_chains = plan.selection_chains.clone();
            (plan, selection_chains)
        };

        if plan.nodes.is_empty() {
            warn!(
                "No available candidate nodes for UDP outbound '{}' ({})",
                outbound_name, client_addr
            );
            let group_manager = self.group_manager.read().clone();
            for node in group_manager.leaf_nodes_in_group(&outbound_name) {
                self.alive_set.notify_check_tcp(node.id);
            }
            self.stats.record_error(&outbound_name);
            return Ok(());
        }

        let (connect_timeout, transport_deadline) = {
            let config = self.config.read().await;
            let connect_timeout = Duration::from_millis(config.global.connect_timeout_ms);
            (
                connect_timeout,
                tokio::time::Instant::now() + overall_dial_timeout(connect_timeout),
            )
        };

        // Cold URLTest preparation owns no endpoint state: no lease binding,
        // reply socket, driver, tracker, or application packet exists until
        // a single eligible transport winner has been drained and accepted.
        let scheduler_ipver = plan.ipver;
        let plan_mode = plan.mode;
        let score_feedback = plan.feedback;
        // Only a literal direct route keeps a mark, and Cold URLTest is always
        // a group route, so speculative preparation never needs one.
        debug_assert!(plan_mode != SelectionPlanMode::ColdUrlTest || mark.is_none());
        let runtime_generation = self.runtime_registry.read().clone();
        let prepare_generation = Arc::clone(&runtime_generation);
        let prepare: UdpPrepare<(
            PreparedEndpointTransport,
            Option<crate::group::ScoreReporter>,
            Vec<String>,
        )> = {
            let registry = self.proxy_registry.clone();
            let stats = self.stats.clone();
            let feedback = score_feedback.clone();
            #[cfg(feature = "rprx")]
            let udp_pool = Arc::clone(&self.udp_pool);
            #[cfg(feature = "rprx")]
            let alive_set = Arc::clone(&self.alive_set);
            let target_domain = target_domain.clone();
            Arc::new(move |index: usize, node: Node| {
                let registry = registry.clone();
                let stats = stats.clone();
                let runtime_generation = Arc::clone(&prepare_generation);
                let feedback = feedback.get(index).cloned().flatten();
                let selection_chain = selection_chains.get(index).cloned().unwrap_or_default();
                #[cfg(feature = "rprx")]
                let udp_pool = Arc::clone(&udp_pool);
                #[cfg(feature = "rprx")]
                let alive_set = Arc::clone(&alive_set);
                let target_domain = target_domain.clone();
                Box::pin(async move {
                    let reporter = feedback
                        .as_ref()
                        .map(crate::group::ScoreAttempt::begin)
                        .transpose()?
                        .map(crate::group::ScoreBusinessGuard::start);
                    let dial_started_at = std::time::Instant::now();
                    let flow_transport = async {
                        (if let Some(mark) = mark {
                            registry
                                .dial_udp_transport_runtime_marked(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                    mark,
                                )
                                .await
                        } else {
                            registry
                                .dial_udp_transport_runtime(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                        })
                        .map(honk_outbound::proxy::PreparedUdpTransport::ready)
                        .map(PreparedEndpointTransport::Flow)
                    };
                    let result = {
                        #[cfg(feature = "rprx")]
                        if let Some(path) = vless_source_path(&node, original_dst.port()) {
                            let runtime = runtime_generation.get(&node.id).ok_or_else(|| {
                                anyhow::anyhow!(
                                    "node {} is not in the captured runtime generation",
                                    node.id
                                )
                            })?;
                            udp_pool
                                .prepare_vless_source(
                                    Arc::clone(&runtime_generation),
                                    runtime,
                                    client_addr,
                                    path,
                                    target_is_domain.then_some(original_dst),
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                    Arc::clone(&alive_set),
                                    Arc::clone(&stats),
                                    scheduler_ipver,
                                )
                                .await
                                .map(PreparedEndpointTransport::Source)
                        } else if plan_mode == SelectionPlanMode::ColdUrlTest {
                            registry
                                .dial_udp_transport_speculative(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                                .map(PreparedEndpointTransport::Flow)
                        } else {
                            flow_transport.await
                        }
                        #[cfg(not(feature = "rprx"))]
                        if plan_mode == SelectionPlanMode::ColdUrlTest {
                            registry
                                .dial_udp_transport_speculative(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                                .map(PreparedEndpointTransport::Flow)
                        } else {
                            flow_transport.await
                        }
                    };
                    stats.record_udp_dial_latency(dial_started_at.elapsed());
                    match result {
                        Ok(transport) => Ok((transport, reporter, selection_chain)),
                        Err(error) => {
                            if let Some(reporter) = &reporter {
                                reporter.setup_failed(score_runtime_outcome(
                                    &runtime_generation,
                                    &error,
                                ));
                            }
                            Err(error)
                        }
                    }
                })
            })
        };
        let callbacks = UdpStaggerCallbacks {
            allows_target: Arc::new(move |node| {
                honk_outbound::descriptor::udp_target_allowed(node, original_dst.port())
            }),
            is_eligible: {
                let group_manager = self.group_manager.clone();
                Arc::new(move |node| {
                    group_manager.read().is_node_selectable_for_domain(
                        node.id,
                        ProbeDomain::DataUdp,
                        scheduler_ipver,
                    )
                })
            },
            on_dial_error: {
                let alive_set = self.alive_set.clone();
                let runtime_generation = Arc::clone(&runtime_generation);
                Arc::new(move |node| {
                    report_dial_failure_if_current(
                        &runtime_generation,
                        &alive_set,
                        node.id,
                        ProbeDomain::DataUdp,
                        scheduler_ipver,
                    );
                })
            },
            on_attempt: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_attempt())
            },
            on_winner: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_winner())
            },
            on_cancellation: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_cancellation())
            },
        };
        let Some((node, (prepared_transport, score_reporter, selection_chain))) = prepare_udp_plan(
            plan_mode,
            plan.nodes,
            transport_deadline,
            prepare,
            callbacks,
        )
        .await?
        else {
            debug!(
                "All UDP transport preparations failed for '{}'",
                outbound_name
            );
            self.stats.record_error(&outbound_name);
            return Ok(());
        };

        // The prepared winner is bound only after every speculative loser has
        // been aborted/drained. Close the death-before-bind race again before
        // creating endpoint state or allowing the driver to send.
        if !lease.bind_selected_node(node.id) {
            if let Some(reporter) = &score_reporter {
                reporter.finish(crate::group::ScoreOutcome::Cancelled);
            }
            return Err(anyhow::anyhow!(
                "UDP initializer generation was cancelled before winner bind"
            ));
        }
        if !lease.still_initializing()
            || !self.group_manager.read().is_node_selectable_for_domain(
                node.id,
                ProbeDomain::DataUdp,
                scheduler_ipver,
            )
        {
            lease.clear_selected_node();
            if let Some(reporter) = &score_reporter {
                reporter.finish(crate::group::ScoreOutcome::Cancelled);
            }
            return Err(anyhow::anyhow!(
                "UDP winner '{}' became ineligible before endpoint setup",
                node.name
            ));
        }
        // Final promotion remains pre-publication and inside the unchanged
        // absolute preparation deadline.
        #[cfg(feature = "rprx")]
        let source_pool = Arc::clone(&self.udp_pool);
        let transport = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(transport_deadline) => {
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::Timeout);
                }
                return Err(anyhow::anyhow!(
                    "UDP transport preparation exceeded its overall deadline"
                ));
            }
            result = async move {
                match prepared_transport {
                    PreparedEndpointTransport::Flow(prepared) => prepared
                        .commit()
                        .await
                        .map(CommittedEndpointTransport::Flow),
                    #[cfg(feature = "rprx")]
                    PreparedEndpointTransport::Source(prepared) => prepared
                        .commit(&source_pool)
                        .await
                        .map(CommittedEndpointTransport::Source),
                }
            } => match result {
                Ok(transport) => transport,
                Err(error) => {
                    if let Some(reporter) = &score_reporter {
                        reporter.finish(score_runtime_outcome(&runtime_generation, &error));
                    }
                    return Err(error);
                }
            }
        };
        if let Some(reporter) = &score_reporter {
            reporter.setup_succeeded();
        }

        // Both capacity (at reservation time) and anyfrom creation happen
        // after the winner is finalized and before the only first send. Any
        // failure is fail-closed; there is no listener-socket fallback.
        let reply_ready_started = std::time::Instant::now();
        let reply_socket = match self.udp_pool.create_reply_socket(original_dst) {
            Ok(socket) => Arc::new(socket),
            Err(error) => {
                self.stats
                    .record_udp_reply_ready_latency(reply_ready_started.elapsed());
                self.stats.record_error(&outbound_name);
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::Cancelled);
                }
                return Err(error.into());
            }
        };
        self.stats
            .record_udp_reply_ready_latency(reply_ready_started.elapsed());

        let endpoint = Arc::new(match transport {
            CommittedEndpointTransport::Flow(transport) => {
                let relay_addr = transport.relay_addr();
                let endpoint = UdpEndpoint::new_scored(
                    transport,
                    relay_addr,
                    target_is_domain,
                    node.id,
                    scheduler_ipver,
                    score_reporter,
                );
                endpoint.record_pending_reply_peer(relay_addr);
                endpoint
            }
            #[cfg(feature = "rprx")]
            CommittedEndpointTransport::Source(attachment) => UdpEndpoint::new_source_scored(
                attachment,
                original_dst,
                target_domain.as_deref(),
                Arc::clone(&reply_socket),
                self.stats.outbound_tracker(&outbound_name),
                node.id,
                scheduler_ipver,
                score_reporter,
            ),
        });

        let tracker_id = if let Some(conn_id) = self.connection_tracker.register_if_enabled(|| {
            let id = uuid::Uuid::new_v4().to_string();
            let (rule, rule_payload) =
                matched_rule.unwrap_or_else(|| ("Fallback".to_string(), String::new()));
            let (upload, download) = endpoint.byte_counters();
            crate::connection_tracker::ConnectionEntry {
                id,
                source: client_addr.to_string(),
                destination: original_dst.to_string(),
                proxy: node.name.clone(),
                rule,
                rule_payload,
                chains: connection_chains(selection_chain, &node.name),
                upload,
                download,
                start_time: std::time::Instant::now(),
                domain: quic_domain.clone(),
                network: "udp".to_string(),
                process: handoff.as_ref().and_then(|ho| ho.process_name()),
                process_path: None,
            }
        }) {
            endpoint.set_tracker(conn_id.clone());
            if !lease.set_tracker_id(conn_id.clone()) {
                // The generation was cancelled between route selection and
                // registration. No pool entry owns this tracker, so retire it
                // directly rather than leaking it.
                self.connection_tracker.remove(&conn_id);
                return Err(anyhow::anyhow!(
                    "UDP initializer generation was cancelled before tracker attachment"
                ));
            }
            Some(conn_id)
        } else {
            None
        };

        let queue_rx = match follower_rx {
            // Already taken while collecting a fragmented ClientHello.
            Some(rx) => rx,
            None => lease.take_queue_receiver().ok_or_else(|| {
                anyhow::anyhow!("UDP initializer lost its bounded queue before driver start")
            })?,
        };
        let mut driver = self.udp_pool.spawn_driver(
            client_addr,
            original_dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            reply_socket,
            self.alive_set.clone(),
            self.stats.clone(),
            outbound_name.clone(),
        );
        driver.wait_ready().await?;
        if !lease.still_initializing() {
            return Err(anyhow::anyhow!(
                "UDP initializer generation was retired before ready commit"
            ));
        }
        if !lease.commit_ready(Arc::clone(&endpoint)) {
            return Err(anyhow::anyhow!(
                "UDP initializer generation was cancelled before ready commit"
            ));
        }
        let first = lease.take_first().ok_or_else(|| {
            anyhow::anyhow!("UDP initializer lost its first packet before driver start")
        })?;
        driver.start_with_followers(first, sniffed_followers)?;
        if let Some(conn_id) = tracker_id {
            self.spawn_process_path_enrichment(conn_id, handoff.as_ref());
        }
        if let Err(error) = driver.wait_first_ack().await {
            // First-send failures are terminal for this endpoint; once the
            // transport call starts, the packet is never replayed.
            self.stats.record_error(&outbound_name);
            return Err(error.into());
        }
        debug!(
            network = "udp",
            outbound = %outbound_name,
            dialer = %node.name,
            sniffed = quic_domain.as_deref().unwrap_or(""),
            ip = %original_dst,
            src = %client_addr,
            "UDP connection: {} -> {} via {} (endpoint driver ready)",
            client_addr,
            original_dst,
            node.name,
        );
        Ok(())
    }

    /// A fragmented ClientHello: feed queued follower Initials to the
    /// sniffer until it resolves, or the packet/time budget runs out.
    /// Fragments of one flight arrive back-to-back, so the budget is small
    /// and the common single-Initial path never enters this loop. Retained
    /// followers are returned in receive order for the canonical UDP
    /// endpoint driver.
    async fn collect_initial_fragments(
        &self,
        sniffer_key: crate::control::packet_sniffer::PacketSnifferKey,
        rx: &mut tokio::sync::mpsc::Receiver<crate::control::udp_endpoint::QueuedDatagram>,
    ) -> (
        crate::control::packet_sniffer::QuicSniffOutcome,
        Vec<crate::control::udp_endpoint::QueuedDatagram>,
    ) {
        use crate::control::packet_sniffer::QuicSniffOutcome;
        const MAX_FRAGMENTS: u32 = 8;
        const MAX_WAIT: Duration = Duration::from_millis(250);
        let deadline = tokio::time::Instant::now() + MAX_WAIT;
        let mut outcome = QuicSniffOutcome::Incomplete;
        let mut collected = Vec::with_capacity(MAX_FRAGMENTS as usize);
        for _ in 0..MAX_FRAGMENTS {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(datagram)) => {
                    outcome = self
                        .sniffer_pool
                        .feed_quic_initial(sniffer_key, datagram.payload());
                    collected.push(datagram);
                    if !matches!(outcome, QuicSniffOutcome::Incomplete) {
                        break;
                    }
                }
                _ => break,
            }
        }
        (outcome, collected)
    }
}
