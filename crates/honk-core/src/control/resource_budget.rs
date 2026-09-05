//! Immutable process-wide descriptor partitioning for the control plane.

use crate::control::udp_endpoint::{MAX_ENDPOINTS, MAX_REPLY_SOCKETS_PER_ENDPOINT};
use crate::pool::MAX_TOTAL_ENTRIES;

pub(crate) const MAX_EFFECTIVE_NOFILE: usize = 1_048_576;
const MAX_FIXED_RESERVE: usize = 256;
const MAX_ACTIVE_TCP_FLOWS: usize = 16_384;
const MAX_TRANSIENT_DIALS: usize = 1_024;
const MAX_UDP_SLOW_PATH: usize = 256;
const MAX_DNS_SLOW_PATH: usize = 256;
const TCP_FLOW_DESCRIPTOR_COST: usize = 6;
// One upstream socket, a possible SOCKS5 control connection, and every reply socket.
const UDP_ENDPOINT_DESCRIPTOR_COST: usize = 2 + MAX_REPLY_SOCKETS_PER_ENDPOINT;
// Keep half of the non-TCP budget available for bursty gateway DNS/UDP work.
const ELASTIC_NON_TCP_RESERVE_DIVISOR: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResourceBudget {
    pub effective_nofile: usize,
    pub fixed_reserve: usize,
    pub active_tcp_flows: usize,
    pub tcp_pool_entries: usize,
    pub transient_dials: usize,
    pub udp_endpoints: usize,
    pub udp_slow_path: usize,
    pub dns_slow_path: usize,
}

impl ResourceBudget {
    pub(crate) fn for_nofile(nofile: usize) -> Self {
        let effective_nofile = nofile.min(MAX_EFFECTIVE_NOFILE);
        let fixed_reserve = (effective_nofile / 8).min(MAX_FIXED_RESERVE);
        let allocatable = effective_nofile.saturating_sub(fixed_reserve);

        let active_tcp_descriptors = (allocatable / 4)
            .min(MAX_ACTIVE_TCP_FLOWS * TCP_FLOW_DESCRIPTOR_COST)
            / TCP_FLOW_DESCRIPTOR_COST
            * TCP_FLOW_DESCRIPTOR_COST;
        let active_tcp_flows = active_tcp_descriptors / TCP_FLOW_DESCRIPTOR_COST;
        let after_active_tcp = allocatable.saturating_sub(active_tcp_descriptors);

        let tcp_pool_entries = (allocatable / 8)
            .min(MAX_TOTAL_ENTRIES)
            .min(after_active_tcp);
        let after_tcp_pool = after_active_tcp.saturating_sub(tcp_pool_entries);

        let transient_dials = if allocatable == 0 {
            0
        } else {
            allocatable
                .div_ceil(16)
                .min(MAX_TRANSIENT_DIALS)
                .min(after_tcp_pool)
        };
        let after_dials = after_tcp_pool.saturating_sub(transient_dials);
        let udp_endpoints = (after_dials / UDP_ENDPOINT_DESCRIPTOR_COST).min(MAX_ENDPOINTS);

        Self {
            effective_nofile,
            fixed_reserve,
            active_tcp_flows,
            tcp_pool_entries,
            transient_dials,
            udp_endpoints,
            udp_slow_path: udp_endpoints.min(MAX_UDP_SLOW_PATH),
            dns_slow_path: transient_dials.min(MAX_DNS_SLOW_PATH),
        }
    }

    pub(crate) fn clamp_dials(self, requested: usize) -> usize {
        requested.max(1).min(self.transient_dials)
    }
    /// Returns the TCP permit target after borrowing currently idle non-TCP headroom.
    pub(crate) fn elastic_tcp_flows(self, active_permits: usize, open_fds: usize) -> usize {
        let floor = self.active_tcp_flows;
        if floor == 0 {
            return active_permits;
        }
        let non_tcp_budget = self
            .tcp_pool_entries
            .saturating_add(self.transient_dials)
            .saturating_add(
                self.udp_endpoints
                    .saturating_mul(UDP_ENDPOINT_DESCRIPTOR_COST),
            );
        let non_tcp_used = open_fds
            .saturating_sub(self.fixed_reserve)
            .saturating_sub(active_permits.saturating_mul(TCP_FLOW_DESCRIPTOR_COST));
        let idle_non_tcp = non_tcp_budget
            .saturating_sub(non_tcp_budget / ELASTIC_NON_TCP_RESERVE_DIVISOR)
            .saturating_sub(non_tcp_used);
        floor
            .saturating_add(idle_non_tcp / TCP_FLOW_DESCRIPTOR_COST)
            .min(floor.saturating_mul(2))
            .max(active_permits)
    }

    #[cfg(test)]
    fn accounted_descriptors(self) -> usize {
        self.fixed_reserve
            .saturating_add(
                self.active_tcp_flows
                    .saturating_mul(TCP_FLOW_DESCRIPTOR_COST),
            )
            .saturating_add(self.tcp_pool_entries)
            .saturating_add(self.transient_dials)
            .saturating_add(
                self.udp_endpoints
                    .saturating_mul(UDP_ENDPOINT_DESCRIPTOR_COST),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitions_never_exceed_effective_limit() {
        for nofile in [
            0,
            1,
            16,
            64,
            256,
            1_024,
            4_096,
            MAX_EFFECTIVE_NOFILE,
            usize::MAX,
        ] {
            let budget = ResourceBudget::for_nofile(nofile);
            assert_eq!(budget.effective_nofile, nofile.min(MAX_EFFECTIVE_NOFILE));
            assert!(budget.accounted_descriptors() <= budget.effective_nofile);
            assert!(budget.active_tcp_flows <= MAX_ACTIVE_TCP_FLOWS);
            assert!(budget.tcp_pool_entries <= MAX_TOTAL_ENTRIES);
            assert!(budget.transient_dials <= MAX_TRANSIENT_DIALS);
            assert!(budget.udp_endpoints <= MAX_ENDPOINTS);
            assert!(budget.udp_slow_path <= budget.udp_endpoints);
            assert!(budget.dns_slow_path <= budget.transient_dials);
        }
    }

    #[test]
    fn worst_case_udp_endpoint_max_fits_descriptor_partition() {
        for nofile in [64, 1_024, 4_096, usize::MAX] {
            let budget = ResourceBudget::for_nofile(nofile);
            let non_udp_descriptors = budget.fixed_reserve
                + budget.active_tcp_flows * TCP_FLOW_DESCRIPTOR_COST
                + budget.tcp_pool_entries
                + budget.transient_dials;
            let endpoint_descriptors = budget.udp_endpoints * (2 + MAX_REPLY_SOCKETS_PER_ENDPOINT);

            assert!(non_udp_descriptors + endpoint_descriptors <= budget.effective_nofile);
        }
    }

    #[test]
    fn elastic_tcp_flows_borrow_only_idle_non_tcp_headroom() {
        let budget = ResourceBudget::for_nofile(4_096);
        let tcp_only_fds =
            budget.fixed_reserve + budget.active_tcp_flows * TCP_FLOW_DESCRIPTOR_COST;
        let fully_reserved_fds = tcp_only_fds
            + budget.tcp_pool_entries
            + budget.transient_dials
            + budget.udp_endpoints * UDP_ENDPOINT_DESCRIPTOR_COST;

        let borrowed = budget.elastic_tcp_flows(budget.active_tcp_flows, tcp_only_fds);
        assert!(borrowed > budget.active_tcp_flows);
        assert!(borrowed <= budget.active_tcp_flows * 2);
        assert_eq!(
            budget.elastic_tcp_flows(0, fully_reserved_fds),
            budget.active_tcp_flows
        );
        assert_eq!(budget.elastic_tcp_flows(300, fully_reserved_fds), 300);

        let cap = ResourceBudget::for_nofile(usize::MAX);
        let cap_tcp_only_fds = cap.fixed_reserve + cap.active_tcp_flows * TCP_FLOW_DESCRIPTOR_COST;
        let cap_borrowed = cap.elastic_tcp_flows(cap.active_tcp_flows, cap_tcp_only_fds);
        assert!(cap_borrowed >= cap.active_tcp_flows);
        assert!(cap_borrowed <= cap.active_tcp_flows * 2);
    }
    #[test]
    fn configured_dials_are_clamped_to_reserved_ceiling() {
        let budget = ResourceBudget::for_nofile(1_024);
        assert_eq!(budget.clamp_dials(0), 1);
        assert_eq!(budget.clamp_dials(32), 32);
        assert_eq!(budget.clamp_dials(usize::MAX), 56);
    }
}
