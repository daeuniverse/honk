//! Candidate capability and liveness filtering before any policy pick.

use super::*;

impl GroupManager {
    /// Whether a node is selectable for this traffic domain and IP version.
    ///
    /// UDP capability is required even without health tracking; block remains
    /// a terminal action. Data UDP accepts either UDP probe domain after UDP
    /// state exists; otherwise capable nodes inherit TCP liveness.
    pub fn is_node_selectable_for_domain(
        &self,
        node_id: uuid::Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> bool {
        if matches!(domain, ProbeDomain::DataUdp | ProbeDomain::DnsUdp)
            && let Some(node) = self.nodes.get(&node_id)
            && node.protocol() != honk_config::types::NodeProtocol::Block
            && !(crate::descriptor::descriptor(node.protocol()).supports_udp)(node)
        {
            return false;
        }
        let Some(alive) = &self.alive_set else {
            return true;
        };
        if domain == ProbeDomain::DataUdp {
            return if alive.has_udp_state(node_id) {
                alive.is_alive_for(node_id, ProbeDomain::DataUdp, ipver)
                    || alive.is_alive_for(node_id, ProbeDomain::DnsUdp, ipver)
            } else {
                alive.is_alive_for(node_id, ProbeDomain::Tcp, ipver)
            };
        }
        alive.is_alive_for(node_id, domain, ipver)
    }

    /// Keep only capable, alive leaves; absent health tracking skips only health.
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
        routes: bool,
    ) -> Vec<Candidate<'a>> {
        if routes {
            candidates = self.retain_exit_selectable(candidates, group, domain, ipver);
        } else {
            debug_assert!(group.exit.is_none(), "group '{}' has an exit", group.name);
            debug_assert!(
                candidates.iter().all(|candidate| self
                    .dials_its_leaf(candidate, SelectionNetwork::from_probe_domain(domain))),
                "group '{}' has a candidate that does not dial its leaf",
                group.name
            );
        }
        let check_url = group.check_url.as_deref();
        if domain == ProbeDomain::Tcp
            && let Some(url) = check_url
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
                    let eligible = alive.is_alive_for_url(c.tag(), url);
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
                let eligible = self.is_node_selectable_for_domain(c.node.id, domain, ipver);
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
