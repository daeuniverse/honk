#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    all(not(test), not(feature = "dns-bench"), not(feature = "clash-api")),
    expect(
        dead_code,
        reason = "DNS statistics are exposed only with the Clash API"
    )
)]
pub(crate) struct DnsStatsSnapshot {
    pub(crate) cache_hit: u64,
    pub(crate) cache_miss: u64,
    pub(crate) cache_stale: u64,
    pub(crate) singleflight_key_saturation: u64,
    pub(crate) singleflight_waiter_saturation: u64,
    pub(crate) singleflight_cancel: u64,
    pub(crate) singleflight_retry: u64,
    pub(crate) singleflight_rejected: u64,
    pub(crate) singleflight_amplification_avoided: u64,
    pub(crate) persistence_drop: u64,
    pub(crate) persistence_flush_failure: u64,
    pub(crate) runtime_retirement_timeout: u64,
    pub(crate) runtime_forced_close: u64,
    pub(crate) transport_init: u64,
    pub(crate) transport_reset: u64,
    pub(crate) socket_admission_refused: u64,
    pub(crate) socket_admission_timeout: u64,
    pub(crate) proxy_admission_timeout: u64,
    pub(crate) pressure_retired_udp_pool: u64,
    pub(crate) pressure_retired_transport: u64,
    pub(crate) projection_stale_generation: u64,
    pub(crate) projection_write_failure: u64,
    pub(crate) projection_retry: u64,
    pub(crate) outcome_positive: u64,
    pub(crate) outcome_nodata: u64,
    pub(crate) outcome_nxdomain: u64,
    pub(crate) outcome_servfail: u64,
    pub(crate) outcome_rejected: u64,
    pub(crate) outcome_error: u64,
}

impl DnsStatsSnapshot {
    #[cfg(test)]
    pub(crate) const fn delta(self, earlier: Self) -> Self {
        Self {
            cache_hit: self.cache_hit.saturating_sub(earlier.cache_hit),
            cache_miss: self.cache_miss.saturating_sub(earlier.cache_miss),
            cache_stale: self.cache_stale.saturating_sub(earlier.cache_stale),
            singleflight_key_saturation: self
                .singleflight_key_saturation
                .saturating_sub(earlier.singleflight_key_saturation),
            singleflight_waiter_saturation: self
                .singleflight_waiter_saturation
                .saturating_sub(earlier.singleflight_waiter_saturation),
            singleflight_cancel: self
                .singleflight_cancel
                .saturating_sub(earlier.singleflight_cancel),
            singleflight_retry: self
                .singleflight_retry
                .saturating_sub(earlier.singleflight_retry),
            singleflight_rejected: self
                .singleflight_rejected
                .saturating_sub(earlier.singleflight_rejected),
            singleflight_amplification_avoided: self
                .singleflight_amplification_avoided
                .saturating_sub(earlier.singleflight_amplification_avoided),
            persistence_drop: self
                .persistence_drop
                .saturating_sub(earlier.persistence_drop),
            persistence_flush_failure: self
                .persistence_flush_failure
                .saturating_sub(earlier.persistence_flush_failure),
            runtime_retirement_timeout: self
                .runtime_retirement_timeout
                .saturating_sub(earlier.runtime_retirement_timeout),
            runtime_forced_close: self
                .runtime_forced_close
                .saturating_sub(earlier.runtime_forced_close),
            transport_init: self.transport_init.saturating_sub(earlier.transport_init),
            transport_reset: self.transport_reset.saturating_sub(earlier.transport_reset),
            socket_admission_refused: self
                .socket_admission_refused
                .saturating_sub(earlier.socket_admission_refused),
            socket_admission_timeout: self
                .socket_admission_timeout
                .saturating_sub(earlier.socket_admission_timeout),
            proxy_admission_timeout: self
                .proxy_admission_timeout
                .saturating_sub(earlier.proxy_admission_timeout),
            pressure_retired_udp_pool: self
                .pressure_retired_udp_pool
                .saturating_sub(earlier.pressure_retired_udp_pool),
            pressure_retired_transport: self
                .pressure_retired_transport
                .saturating_sub(earlier.pressure_retired_transport),
            projection_stale_generation: self
                .projection_stale_generation
                .saturating_sub(earlier.projection_stale_generation),
            projection_write_failure: self
                .projection_write_failure
                .saturating_sub(earlier.projection_write_failure),
            projection_retry: self
                .projection_retry
                .saturating_sub(earlier.projection_retry),
            outcome_positive: self
                .outcome_positive
                .saturating_sub(earlier.outcome_positive),
            outcome_nodata: self.outcome_nodata.saturating_sub(earlier.outcome_nodata),
            outcome_nxdomain: self
                .outcome_nxdomain
                .saturating_sub(earlier.outcome_nxdomain),
            outcome_servfail: self
                .outcome_servfail
                .saturating_sub(earlier.outcome_servfail),
            outcome_rejected: self
                .outcome_rejected
                .saturating_sub(earlier.outcome_rejected),
            outcome_error: self.outcome_error.saturating_sub(earlier.outcome_error),
        }
    }
}
