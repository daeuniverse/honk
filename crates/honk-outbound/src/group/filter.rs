//! Candidate capability and liveness filtering before any policy pick.

use super::*;

impl GroupManager {
    /// Whether a node is selectable for this traffic domain and IP version.
    ///
    /// UDP capability is required even without health tracking; block remains
    /// a terminal action. Health is [`Self::is_node_alive_for_domain`].
    pub fn is_node_selectable_for_domain(
        &self,
        node_id: uuid::Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> bool {
        if matches!(domain, ProbeDomain::DataUdp | ProbeDomain::DnsUdp)
            && let Some(node) = self.nodes.get(&node_id)
            && node.protocol() != honk_config::types::NodeProtocol::Block
        {
            if !self.node_carries_udp(node) {
                return false;
            }
            if let Some(hops) = node.resolved_chain_hops()
                && !self.udp_route_path_available(node_id, hops, domain, ipver)
            {
                return false;
            }
        }
        self.is_node_alive_for_domain(node_id, domain, ipver)
    }

    /// Health alone, for a node whose UDP capability its route answers.
    /// Data UDP accepts either UDP probe domain after UDP state exists;
    /// otherwise a node inherits TCP liveness.
    #[inline]
    pub(super) fn is_node_alive_for_domain(
        &self,
        node_id: uuid::Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> bool {
        let Some(alive) = &self.alive_set else {
            return true;
        };
        if domain == ProbeDomain::DataUdp {
            return alive.data_udp_available(node_id, ipver);
        }
        alive.is_alive_for(node_id, domain, ipver)
    }

    /// Whether the node carries UDP itself or through its bound chain exit.
    #[inline]
    pub fn node_carries_udp(&self, node: &Node) -> bool {
        crate::descriptor::node_carries_udp(node, |id| self.nodes.get(id))
    }

    /// Keep only capable, alive leaves; absent health tracking skips only health.
    /// UDP capability belongs to the route when a candidate dials through an exit.
    ///
    /// When the group has a custom `check_url` (sing-box urltest `url`
    /// option), TCP liveness and ranking come from the per-(node, url)
    /// probe state instead of the global one — a node that cannot reach
    /// the group's own target is excluded here even if it is globally
    /// healthy. UDP domains always use the global state.
    ///
    /// Capable, unprobed UDP leaves inherit TCP liveness; explicit failures in
    /// both UDP domains exclude them even while TCP remains alive.
    ///
    /// `routes` is false when selection from the root can produce no route,
    /// so no exit on any candidate's path needs checking.
    pub(super) fn filter_alive_candidates<'a>(
        &self,
        mut candidates: Vec<Candidate<'a>>,
        domain: ProbeDomain,
        ipver: IpVersion,
        group: &Group,
        ancestors: &[&str],
        rules: score::selection::ScoreSelectionRules<'_>,
    ) -> Vec<Candidate<'a>> {
        if rules.routes && self.has_exits() {
            // Children already checked the complete path with these ancestors.
            let udp = domain != ProbeDomain::Tcp;
            candidates.retain(|candidate| {
                let eligible = candidate.via.is_some()
                    || self.leaf_route_available(
                        candidate.node,
                        group,
                        ancestors,
                        domain,
                        Some(ipver),
                        rules.node_targets_only,
                    );
                if !eligible || udp {
                    observation::candidate(
                        candidate,
                        eligible,
                        if eligible {
                            "eligible"
                        } else {
                            "exit_unavailable"
                        },
                    );
                }
                eligible
            });
            if udp {
                return candidates;
            }
        } else {
            debug_assert!(group.exit.is_none(), "group '{}' has an exit", group.name);
            debug_assert!(
                candidates.iter().all(|candidate| self
                    .dials_its_leaf(candidate, SelectionNetwork::from_probe_domain(domain))),
                "group '{}' has a candidate that does not dial its leaf",
                group.name
            );
        }
        if domain == ProbeDomain::Tcp
            && let Some(url) = group.check_url.as_deref()
            && let Some(alive) = &self.alive_set
        {
            // Per-URL state is keyed by member TAG (sing-box RealTag
            // semantics): a sub-group is ranked as a unit — the probe
            // dialed its current pick and recorded the result under the
            // sub-group's tag, so a sub-pick change re-evaluates with the
            // tag's state instead of leaking the old leaf's.
            return candidates
                .into_iter()
                .filter(|c| {
                    let eligible = c.node.protocol() == honk_config::types::NodeProtocol::Block
                        || alive.is_alive_for_url(c.tag(), url);
                    observation::candidate(
                        c,
                        eligible,
                        if eligible {
                            "eligible"
                        } else {
                            "custom_url_unavailable"
                        },
                    );
                    eligible
                })
                .collect();
        }
        candidates
            .into_iter()
            .filter(|c| {
                let eligible = c.node.protocol() == honk_config::types::NodeProtocol::Block
                    || self.is_node_selectable_for_domain(c.node.id, domain, ipver);
                observation::candidate(
                    c,
                    eligible,
                    if eligible {
                        "eligible"
                    } else {
                        "capability_or_health_unavailable"
                    },
                );
                eligible
            })
            .collect()
    }
}
