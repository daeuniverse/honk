#[cfg(feature = "ebpf")]
use super::routing::final_udp_rule_mark;
use super::routing::{build_connection_info, connection_chains};
use crate::control::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use crate::control::udp_endpoint::{UdpEndpoint, UdpInitLease};
use crate::control::*;
use crate::group::{SelectionNetwork, SelectionPlanMode};

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

        let dial_mode = {
            let config = self.config.read().await;
            config
                .global
                .dial_mode
                .parse::<DialMode>()
                .map_err(|_| anyhow::anyhow!("invalid global.dial_mode"))?
        };

        // These checks remain after reservation because DNS and sniffing
        // share this initializer. A staged early exit must retire its held
        // originals immediately.
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

        if !lease.dns_checked() {
            match self
                .dns_controller
                .handle_udp_dns(&data, client_addr, original_dst, None)
                .await
            {
                Ok(true) => {
                    #[cfg(feature = "ebpf")]
                    if let Some((verdicts, identity)) = &pending {
                        verdicts.cancel(*identity).await?;
                    }
                    return Ok(());
                }
                Ok(false) => {}
                Err(error) => {
                    // Keep ordinary UDP forwarding available when DNS control
                    // declines with an error.
                    warn!(
                        "DNS controller error for UDP {} -> {}; continuing UDP: {}",
                        client_addr, original_dst, error
                    );
                }
            }
        }

        let tuples = build_tuples_key(
            original_dst.ip(),
            original_dst.port(),
            client_addr.ip(),
            client_addr.port(),
            17, // UDP
        );
        let handoff = self
            .lookup_udp_handoff(&tuples, lease.decision_token())
            .await?;
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
        let conn_info = build_connection_info(
            quic_domain.clone(),
            original_dst,
            client_addr,
            "udp",
            handoff.as_ref(),
        );
        let route = self
            .prepare_routing(dial_mode, &conn_info, domain_verified, handoff.as_ref())
            .await;
        #[cfg(feature = "ebpf")]
        let reroute_by_sniffed_domain = route.reroute_by_sniffed_domain;
        let matched_rule = route.matched_rule;
        let routed_outbound = route.outbound;
        let must = route.must;
        let routed_mark = route.mark;
        #[cfg(feature = "ebpf")]
        let routed_direct = routed_outbound == "direct";
        let outbound_name = self.apply_mode_override(routed_outbound, must).await;
        let target_domain = if matches!(
            outbound_name.as_str(),
            "direct" | "block" | "must_rules" | "control_plane_routing"
        ) {
            None
        } else {
            quic_domain.clone()
        };
        #[cfg(feature = "ebpf")]
        let final_rule_mark = final_udp_rule_mark(routed_direct, &outbound_name, routed_mark);
        #[cfg(not(feature = "ebpf"))]
        let _ = routed_mark;
        self.stats
            .record_udp_route_latency(route_started_at.elapsed());
        #[cfg(feature = "ebpf")]
        if let Some((verdicts, identity)) = &pending {
            match outbound_name.as_str() {
                "direct" => {
                    verdicts
                        .activate_direct(*identity, &mut lease, final_rule_mark)
                        .await?;
                    if let Some(domain) = &quic_domain
                        && Self::should_write_sniffed_domain_bitmap(
                            handoff.as_ref(),
                            reroute_by_sniffed_domain,
                        )
                    {
                        self.push_sniffed_domain_bitmap(&conn_info, domain, original_dst.ip())
                            .await;
                    }
                    return Ok(());
                }
                "block" => {
                    verdicts.block(*identity, &mut lease).await?;
                    return Ok(());
                }
                _ => {
                    let final_outbound = self.outbound_name_to_index(&outbound_name).await;
                    verdicts
                        .activate_proxy(*identity, &lease, final_outbound, final_rule_mark)
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

        let connect_timeout = {
            let config = self.config.read().await;
            std::time::Duration::from_millis(config.global.connect_timeout_ms)
        };

        // Cold URLTest preparation owns no endpoint state: no lease binding,
        // reply socket, driver, tracker, or application packet exists until
        // a single eligible transport winner has been drained and accepted.
        let scheduler_ipver = plan.ipver;
        let plan_mode = plan.mode;
        let score_feedback = plan.feedback;
        let runtime_generation = self.runtime_registry.read().clone();
        let prepare_generation = Arc::clone(&runtime_generation);
        let prepare: UdpPrepare<(
            honk_outbound::proxy::PreparedUdpTransport,
            Option<crate::group::ScoreReporter>,
            Vec<String>,
        )> = {
            let registry = self.proxy_registry.clone();
            let stats = self.stats.clone();
            let feedback = score_feedback.clone();
            Arc::new(move |index: usize, node: Node| {
                let registry = registry.clone();
                let stats = stats.clone();
                let runtime_generation = Arc::clone(&prepare_generation);
                let feedback = feedback.get(index).cloned().flatten();
                let selection_chain = selection_chains.get(index).cloned().unwrap_or_default();
                let target_domain = target_domain.clone();
                Box::pin(async move {
                    let reporter = feedback.map(|feedback| feedback.start());
                    let dial_started_at = std::time::Instant::now();
                    let result = if plan_mode == SelectionPlanMode::ColdUrlTest {
                        registry
                            .dial_udp_transport_speculative(
                                Arc::clone(&runtime_generation),
                                node.id,
                                original_dst,
                                target_domain.as_deref(),
                                connect_timeout,
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
                            .map(honk_outbound::proxy::PreparedUdpTransport::ready)
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
        let Some((node, (prepared_transport, score_reporter, selection_chain))) =
            prepare_udp_plan(plan_mode, plan.nodes, prepare, callbacks).await
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
        // Promotion is explicit and still pre-publication: detached AnyTLS
        // sessions and QUIC clients become generation-owned only for the
        // finalized winner.
        let transport = match prepared_transport.commit().await {
            Ok(transport) => transport,
            Err(error) => {
                if let Some(reporter) = &score_reporter {
                    reporter.finish(score_runtime_outcome(&runtime_generation, &error));
                }
                return Err(error);
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

        let relay_addr = transport.relay_addr();
        let endpoint = Arc::new(UdpEndpoint::new_scored(
            transport,
            relay_addr,
            node.id,
            scheduler_ipver,
            score_reporter,
        ));
        endpoint.record_pending_reply_peer(relay_addr);

        let conn_id = uuid::Uuid::new_v4().to_string();
        let (rule, rule_payload) = matched_rule
            .clone()
            .unwrap_or_else(|| ("Fallback".to_string(), String::new()));
        let chains = connection_chains(selection_chain, &node.name);
        let (conn_upload, conn_download) = endpoint.byte_counters();
        self.connection_tracker
            .register(crate::connection_tracker::ConnectionEntry {
                id: conn_id.clone(),
                source: client_addr.to_string(),
                destination: original_dst.to_string(),
                proxy: node.name.clone(),
                rule,
                rule_payload,
                chains,
                upload: conn_upload,
                download: conn_download,
                start_time: std::time::Instant::now(),
                domain: quic_domain.clone(),
                network: "udp".to_string(),
                process: handoff.as_ref().and_then(|ho| ho.process_name()),
                process_path: None,
            });
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
        self.spawn_process_path_enrichment(conn_id, handoff.as_ref());
        if let Err(error) = driver.wait_first_ack().await {
            // First-send failures are terminal for this endpoint; once the
            // transport call starts, the packet is never replayed.
            self.stats.record_error(&outbound_name);
            return Err(error.into());
        }
        debug!(
            "Proxying UDP {} -> {} via {} (endpoint driver ready)",
            client_addr, original_dst, node.name
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
