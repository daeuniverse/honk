use super::handoff::HandoffResult;
use crate::control::*;
pub(super) fn connection_chains(mut selection_chain: Vec<String>, node_name: &str) -> Vec<String> {
    if selection_chain.last().map(String::as_str) != Some(node_name) {
        selection_chain.push(node_name.to_owned());
    }
    selection_chain.reverse();
    selection_chain
}

#[derive(Debug)]
pub(super) struct RoutingDecision {
    pub(super) outbound: String,
    pub(super) must: bool,
    pub(super) mark: Option<honk_outbound::proxy::DirectMark>,
    pub(super) matched_rule: Option<(String, String)>,
    pub(super) reroute_by_sniffed_domain: bool,
    #[cfg(feature = "native-api")]
    pub(super) native_route: Option<super::observation::RouteObservation>,
}

impl RoutingDecision {
    /// Installs a mode override's replacement outbound, if any. A rule mark
    /// survives only on a routed `direct` flow that remains `direct`.
    pub(super) fn apply_final_outbound(&mut self, replacement: Option<String>) {
        let routed_direct = self.outbound == "direct";
        if let Some(outbound) = replacement {
            self.outbound = outbound;
        }
        if !routed_direct || self.outbound != "direct" {
            self.mark = None;
        }
    }
}

pub(super) fn build_connection_info(
    domain: Option<String>,
    original_dst: std::net::SocketAddr,
    client_addr: std::net::SocketAddr,
    protocol: &'static str,
    handoff: Option<&HandoffResult>,
) -> ConnectionInfo {
    ConnectionInfo {
        domain,
        dst_ip: original_dst.ip(),
        dst_port: original_dst.port(),
        src_ip: client_addr.ip(),
        src_port: client_addr.port(),
        protocol,
        process_name: handoff.and_then(|ho| ho.process_name()),
        mac: handoff.and_then(|ho| ho.mac_address()),
        dscp: handoff.map(|ho| ho.dscp),
    }
}

impl ControlPlaneHandle {
    /// Verify that a sniffed domain actually resolves to the given IP address.
    ///
    /// This is used by `dial_mode: domain` to prevent routing based on a fake
    /// SNI sent by the client. Both IPv4 and IPv6 results are checked.
    ///
    /// When the connection is dual-stack but our resolver only returns the
    /// other family (common when the DNS strategy suppresses AAAA — e.g.
    /// `ipversion_prefer: 4` with A answers present, or an only-mode), the
    /// check **trusts the SNI** instead of discarding it.
    /// Falling back to IP-only would mis-route CDN IPv6 (e.g. `tracker.m-team.cc`
    /// on Cloudflare AAAA) via `dport(443) → proxy` despite
    /// `domain(keyword: m-team) → direct`.
    pub(super) async fn verify_domain_reality(
        &self,
        domain: &str,
        expected: std::net::IpAddr,
        source: std::net::SocketAddr,
    ) -> RealityOutcome {
        let dns_timeout = std::time::Duration::from_millis(
            self.config.read().await.global.dns_resolve_timeout_ms,
        );
        let resolution = self.dns_resolver.resolve_for_source(domain, source);
        crate::observe::scope_pin!(resolution);
        let resolution =
            crate::observe::flows::dns::scope_purpose("domain_verification", resolution);
        match tokio::time::timeout(dns_timeout, resolution).await {
            Ok(Ok(resolved)) => {
                match domain_reality_outcome(expected, &resolved.ipv4, &resolved.ipv6) {
                    RealityOutcome::ExactMatch => RealityOutcome::ExactMatch,
                    RealityOutcome::OtherFamilyOnly => {
                        debug!(
                            "Domain reality check: {} has no records for {}; other family present — trusting SNI (got v4={:?} v6={:?})",
                            domain, expected, resolved.ipv4, resolved.ipv6
                        );
                        RealityOutcome::OtherFamilyOnly
                    }
                    RealityOutcome::Mismatch => {
                        debug!(
                            "Domain reality check failed: {} does not resolve to {} (got {:?} {:?})",
                            domain, expected, resolved.ipv4, resolved.ipv6
                        );
                        RealityOutcome::Mismatch
                    }
                }
            }
            Ok(Err(e)) => {
                debug!(
                    "Domain reality check failed: unable to resolve {}: {}",
                    domain, e
                );
                RealityOutcome::Mismatch
            }
            Err(_) => {
                debug!("Domain reality check timed out for {}", domain);
                RealityOutcome::Mismatch
            }
        }
    }

    pub(super) async fn apply_domain_reality_check(
        &self,
        dial_mode: DialMode,
        domain: Option<String>,
        original_dst: std::net::IpAddr,
        client_addr: std::net::SocketAddr,
    ) -> (Option<String>, bool, &'static str) {
        match (dial_mode, domain) {
            (DialMode::Domain, Some(domain)) => {
                match self
                    .verify_domain_reality(&domain, original_dst, client_addr)
                    .await
                {
                    RealityOutcome::ExactMatch => (Some(domain), true, "matched"),
                    RealityOutcome::OtherFamilyOnly => (Some(domain), true, "other_family_trusted"),
                    RealityOutcome::Mismatch => {
                        debug!(domain = %domain, destination = %original_dst,
                            "sniffed domain failed reality check; falling back to IP");
                        (None, false, "failed")
                    }
                }
            }
            (_, domain) => (domain, false, "not_required"),
        }
    }

    /// Whether a sniffed domain should participate in userspace routing.
    /// `domain_verified` gates `domain`; `domain+` preserves the initial
    /// IP-rule decision, while `domain++` always re-evaluates it.
    pub(super) fn should_route_with_sniffed_domain(
        dial_mode: DialMode,
        domain: Option<&str>,
        domain_verified: bool,
    ) -> bool {
        domain.is_some()
            && match dial_mode {
                DialMode::Domain => domain_verified,
                DialMode::DomainPlusPlus => true,
                DialMode::Ip | DialMode::DomainPlus => false,
            }
    }

    /// Whether a sniffed domain is allowed to replace an eBPF handoff.
    /// Reserved handoffs and local `must` decisions remain final.
    pub(super) fn should_reroute_sniffed_domain(
        dial_mode: DialMode,
        domain: Option<&str>,
        domain_verified: bool,
        handoff: Option<&HandoffResult>,
    ) -> bool {
        Self::should_route_with_sniffed_domain(dial_mode, domain, domain_verified)
            && handoff.is_some_and(|handoff| {
                handoff.must == 0
                    && !matches!(
                        handoff.outbound,
                        x if x == OutboundIndex::Direct as u8
                            || x == OutboundIndex::Block as u8
                            || x == OutboundIndex::MustRules as u8
                            || x == OutboundIndex::ControlPlaneRouting as u8
                    )
            })
    }

    pub(super) fn should_write_sniffed_domain_bitmap(
        handoff: Option<&HandoffResult>,
        reroute_by_sniffed_domain: bool,
    ) -> bool {
        reroute_by_sniffed_domain
            || handoff
                .map(|handoff| handoff.outbound == OutboundIndex::ControlPlaneRouting as u8)
                .unwrap_or(true)
    }

    pub(super) async fn prepare_routing(
        &self,
        dial_mode: DialMode,
        conn_info: &ConnectionInfo,
        domain_verified: bool,
        handoff: Option<&HandoffResult>,
        #[cfg(feature = "native-api")] record_route: bool,
    ) -> RoutingDecision {
        let reroute_by_sniffed_domain = Self::should_reroute_sniffed_domain(
            dial_mode,
            conn_info.domain.as_deref(),
            domain_verified,
            handoff,
        );
        if let Some(handoff) = handoff
            && handoff.outbound != OutboundIndex::ControlPlaneRouting as u8
            && !reroute_by_sniffed_domain
            && !self.connection_tracker.needs_rule_details()
        {
            return RoutingDecision {
                outbound: self.outbound_index_to_name(handoff.outbound).await,
                must: handoff.must != 0,
                mark: honk_outbound::proxy::DirectMark::new(handoff.mark),
                matched_rule: None,
                reroute_by_sniffed_domain: false,
                #[cfg(feature = "native-api")]
                native_route: record_route.then(super::observation::RouteObservation::kernel),
            };
        }
        let route_with_domain = Self::should_route_with_sniffed_domain(
            dial_mode,
            conn_info.domain.as_deref(),
            domain_verified,
        ) && (handoff.is_none()
            || handoff.is_some_and(|ho| ho.outbound == OutboundIndex::ControlPlaneRouting as u8)
            || reroute_by_sniffed_domain);
        let mut routing_conn_info = conn_info.clone();
        if !route_with_domain {
            routing_conn_info.domain = None;
        }
        #[cfg(feature = "native-api")]
        let mut native_route = (record_route
            && handoff.is_some_and(|handoff| {
                handoff.outbound != OutboundIndex::ControlPlaneRouting as u8
                    && !reroute_by_sniffed_domain
            }))
        .then(super::observation::RouteObservation::kernel);
        let (userspace_outbound, userspace_must, userspace_mark, matched_rule) = {
            let router = self.router.read().await;
            #[cfg(feature = "native-api")]
            let matched = if record_route
                && native_route.is_none()
                && let Some(native) = &self.native
            {
                let _config = self.config.read().await;
                let generation = self.diagnostics.read().generation;
                let observed = router.route_full_observed(
                    &routing_conn_info,
                    None,
                    crate::observe::flows::MAX_RULE_VALUES,
                );
                let rules = crate::observe::rules::observed_rule_evaluations(
                    &native.instance_id,
                    generation,
                    &router,
                    &observed.rules,
                );
                native_route = Some(super::observation::RouteObservation::userspace(
                    &native.instance_id,
                    generation,
                    &routing_conn_info,
                    &router,
                    observed.matched.as_ref(),
                    rules,
                    observed.truncated,
                ));
                observed.matched
            } else {
                router.route_full(&routing_conn_info)
            };
            #[cfg(not(feature = "native-api"))]
            let matched = router.route_full(&routing_conn_info);
            // First matching rule's action, else the configured fallback action.
            let action = matched.as_ref().map_or(router.fallback(), |hit| hit.action);
            (
                action.outbound.clone(),
                action.must,
                action.mark,
                matched.map(|hit| (hit.rule_type.to_string(), hit.rule_payload.to_string())),
            )
        };
        let (outbound, must, mark) = match handoff {
            Some(ho) => {
                debug!(
                    outbound = ho.outbound,
                    mark = ho.mark,
                    must = ho.must,
                    dscp = ho.dscp,
                    decision_token = ho.decision_token,
                    "eBPF routing handoff"
                );
                if ho.outbound == OutboundIndex::ControlPlaneRouting as u8
                    || reroute_by_sniffed_domain
                {
                    (userspace_outbound, userspace_must, userspace_mark)
                } else {
                    (
                        self.outbound_index_to_name(ho.outbound).await,
                        ho.must != 0,
                        honk_outbound::proxy::DirectMark::new(ho.mark),
                    )
                }
            }
            None => (userspace_outbound, userspace_must, userspace_mark),
        };
        RoutingDecision {
            outbound,
            must,
            mark,
            matched_rule,
            reroute_by_sniffed_domain,
            #[cfg(feature = "native-api")]
            native_route,
        }
    }

    /// Publish all matching domain predicates, independently of the flow's
    /// non-domain conditions. Publication failure remains health-neutral.
    pub(super) async fn push_sniffed_domain_bitmap(&self, domain: &str, dst_ip: std::net::IpAddr) {
        // Keep the same router generation until the backend write completes;
        // reload acquires these locks in this order before replacing either.
        let router = self.router.read().await;
        let Some(bitmap) = router.domain_bitmap(domain) else {
            return;
        };
        let lpm_key = crate::ebpf::maps::ip_addr_to_lpm_key(dst_ip);
        let mut ebpf = self.ebpf.write().await;
        match ebpf.add_domain_ip_bitmap(&lpm_key, &bitmap) {
            Ok(()) => debug!(%domain, %dst_ip, "sniffed domain facts published"),
            Err(error) => {
                debug!(%error, %domain, %dst_ip, "failed to publish sniffed domain facts")
            }
        }
    }
}

/// Outcome of comparing a connection destination IP against DNS answers for
/// the sniffed domain (`dial_mode: domain` reality check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::control) enum RealityOutcome {
    /// Exact IP present in the same-family answer set.
    ExactMatch,
    /// No answers for the connection's family, but the other family has
    /// records — trust SNI (Happy Eyeballs / Ipv4Only DNS / single-stack auth).
    OtherFamilyOnly,
    /// Same-family answers exist but do not contain the destination, or the
    /// domain did not resolve at all.
    Mismatch,
}

/// Pure reality-check decision (unit-tested). See [`ControlPlane::verify_domain_reality`].
pub(in crate::control) fn domain_reality_outcome(
    expected: std::net::IpAddr,
    ipv4: &[std::net::IpAddr],
    ipv6: &[std::net::IpAddr],
) -> RealityOutcome {
    match expected {
        std::net::IpAddr::V4(v4) => {
            if ipv4.iter().any(|ip| ip == &std::net::IpAddr::V4(v4)) {
                RealityOutcome::ExactMatch
            } else if ipv4.is_empty() && !ipv6.is_empty() {
                RealityOutcome::OtherFamilyOnly
            } else {
                RealityOutcome::Mismatch
            }
        }
        std::net::IpAddr::V6(v6) => {
            if ipv6.iter().any(|ip| ip == &std::net::IpAddr::V6(v6)) {
                RealityOutcome::ExactMatch
            } else if ipv6.is_empty() && !ipv4.is_empty() {
                // The m-team.cc / Cloudflare IPv6 case: client dials AAAA anycast
                // while our resolver (often Ipv4Only) only has A records.
                RealityOutcome::OtherFamilyOnly
            } else {
                RealityOutcome::Mismatch
            }
        }
    }
}

#[cfg(test)]
#[path = "sniffed_domain_routing_tests.rs"]
mod sniffed_domain_routing_tests;

#[cfg(all(test, feature = "native-api"))]
mod native_tests {
    use super::*;

    #[tokio::test]
    async fn native_final_handoff_does_not_wait_for_router_evidence() {
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        let plane = crate::control::tests::support::control_plane(config);
        let handle = plane.spawn_handle();
        handle.connection_tracker.disable_api();
        handle.connection_tracker.enable_native();
        let handoff = HandoffResult::from(RoutingHandoffEntry {
            result: RoutingResult {
                outbound: OutboundIndex::Direct as u8,
                ..Default::default()
            },
            ..Default::default()
        });
        let info = build_connection_info(
            None,
            "192.0.2.1:443".parse().unwrap(),
            "127.0.0.1:1234".parse().unwrap(),
            "tcp",
            Some(&handoff),
        );
        let _router = handle.router.write().await;
        let decision = tokio::time::timeout(
            Duration::from_millis(100),
            handle.prepare_routing(DialMode::Ip, &info, false, Some(&handoff), false),
        )
        .await
        .expect("native observation must not repeat routing");
        assert_eq!(decision.outbound, "direct");
        assert!(decision.matched_rule.is_none());
        handle.connection_tracker.disable_native();
    }
}
