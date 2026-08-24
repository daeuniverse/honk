use super::handoff::HandoffResult;
use crate::control::*;
pub(super) fn connection_chains(mut selection_chain: Vec<String>, node_name: &str) -> Vec<String> {
    if selection_chain.last().map(String::as_str) != Some(node_name) {
        selection_chain.push(node_name.to_owned());
    }
    selection_chain.reverse();
    selection_chain
}

#[cfg(any(feature = "ebpf", test))]
pub(super) fn final_udp_rule_mark(
    routed_direct: bool,
    final_outbound: &str,
    routed_mark: u32,
) -> u32 {
    if final_outbound == "direct" && !routed_direct {
        0
    } else {
        routed_mark
    }
}

#[derive(Debug)]
pub(super) struct RoutingDecision {
    pub(super) outbound: String,
    pub(super) must: bool,
    pub(super) mark: u32,
    pub(super) matched_rule: Option<(String, String)>,
    pub(super) reroute_by_sniffed_domain: bool,
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
        source_ip: std::net::IpAddr,
    ) -> bool {
        let dns_timeout = std::time::Duration::from_millis(
            self.config.read().await.global.dns_resolve_timeout_ms,
        );
        match tokio::time::timeout(
            dns_timeout,
            self.dns_resolver.resolve_for_source(domain, source_ip),
        )
        .await
        {
            Ok(Ok(resolved)) => {
                match domain_reality_outcome(expected, &resolved.ipv4, &resolved.ipv6) {
                    RealityOutcome::ExactMatch => true,
                    RealityOutcome::OtherFamilyOnly => {
                        debug!(
                            "Domain reality check: {} has no records for {}; other family present — trusting SNI (got v4={:?} v6={:?})",
                            domain, expected, resolved.ipv4, resolved.ipv6
                        );
                        true
                    }
                    RealityOutcome::Mismatch => {
                        debug!(
                            "Domain reality check failed: {} does not resolve to {} (got {:?} {:?})",
                            domain, expected, resolved.ipv4, resolved.ipv6
                        );
                        false
                    }
                }
            }
            Ok(Err(e)) => {
                debug!(
                    "Domain reality check failed: unable to resolve {}: {}",
                    domain, e
                );
                false
            }
            Err(_) => {
                debug!("Domain reality check timed out for {}", domain);
                false
            }
        }
    }

    pub(super) async fn apply_domain_reality_check(
        &self,
        dial_mode: DialMode,
        domain: Option<String>,
        original_dst: std::net::IpAddr,
        client_addr: std::net::IpAddr,
    ) -> (Option<String>, bool) {
        let domain = match (dial_mode, domain) {
            (DialMode::Domain, Some(domain)) => {
                if self
                    .verify_domain_reality(&domain, original_dst, client_addr)
                    .await
                {
                    Some(domain)
                } else {
                    debug!(
                        domain = %domain,
                        destination = %original_dst,
                        "sniffed domain failed reality check; falling back to IP"
                    );
                    None
                }
            }
            (_, domain) => domain,
        };
        let verified = matches!(dial_mode, DialMode::Domain) && domain.is_some();
        (domain, verified)
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
    ) -> RoutingDecision {
        let reroute_by_sniffed_domain = Self::should_reroute_sniffed_domain(
            dial_mode,
            conn_info.domain.as_deref(),
            domain_verified,
            handoff,
        );
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
        let (userspace_outbound, userspace_must, userspace_mark, matched_rule) = {
            let router = self.router.read().await;
            match router.route_full(&routing_conn_info) {
                Some(route) => (
                    route.outbound_name.to_string(),
                    route.must,
                    route.mark,
                    Some((route.rule_type.to_string(), route.rule_payload.to_string())),
                ),
                None => (router.default_outbound().to_string(), false, 0, None),
            }
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
                        ho.mark,
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
        }
    }

    /// Publish the matched sniffed-domain bitmap so later route-time
    /// decisions can use the learned destination IP. Best-effort: a write
    /// failure never fails the flow.
    pub(super) async fn push_sniffed_domain_bitmap(
        &self,
        conn_info: &ConnectionInfo,
        domain: &str,
        dst_ip: std::net::IpAddr,
    ) {
        let (rule_name, bitmaps) = {
            let router = self.router.read().await;
            match router.route_full(conn_info) {
                Some(matched) => {
                    let rule_name = matched.rule_name.to_string();
                    let bitmaps = {
                        let db = DOMAIN_BITMAPS.read();
                        db.get(&rule_name).cloned().unwrap_or_default()
                    };
                    (rule_name, bitmaps)
                }
                None => return,
            }
        };
        if bitmaps.is_empty() {
            return;
        }
        let mut merged = DomainRouting::default();
        for bm in &bitmaps {
            for (word, value) in merged.bitmap.iter_mut().zip(bm.bitmap) {
                *word |= value;
            }
        }
        let prefix_len = if dst_ip.is_ipv4() { 32 } else { 128 };
        let prefix = format!("{dst_ip}/{prefix_len}");
        let Ok(lpm_key) = cidr_to_lpm_key(&prefix) else {
            return;
        };
        let mut ebpf = self.ebpf.write().await;
        match ebpf.add_domain_ip_bitmap(&lpm_key, &merged) {
            Ok(()) => debug!(
                "DOMAIN_ROUTING_MAP updated: {} -> {} (rule '{}')",
                dst_ip, domain, rule_name
            ),
            Err(error) => warn!(
                "Failed to update DOMAIN_ROUTING_MAP for {} ({}): {}",
                dst_ip, domain, error
            ),
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
