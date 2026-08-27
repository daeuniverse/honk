use crate::control::*;

pub(in crate::control) struct ConnectionGuard {
    drain: Arc<DrainTracker>,
}

impl ConnectionGuard {
    pub(in crate::control) fn new(drain: Arc<DrainTracker>) -> Self {
        drain.increment();
        Self { drain }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.drain.decrement();
    }
}

/// Shared context bundle passed to every connection handler.
/// Bundles all shared fields under a single `Arc` to eliminate
/// per-field atomic reference-count overhead on the hot path.
#[derive(Clone)]
pub(in crate::control) struct ControlPlaneHandle {
    pub(in crate::control) config: Arc<RwLock<Arc<Config>>>,
    pub(in crate::control) router: Arc<RwLock<Router>>,
    pub(in crate::control) proxy_registry: Arc<ProxyRegistry>,
    pub(in crate::control) runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    pub(in crate::control) dns_resolver: Arc<DnsResolver>,
    pub(in crate::control) group_manager: SharedGroupManager,
    pub(in crate::control) stats: Arc<StatsManager>,
    pub(in crate::control) ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    pub(in crate::control) udp_pool: Arc<UdpEndpointPool>,
    #[cfg(feature = "ebpf")]
    pub(in crate::control) pending_udp_verdicts:
        Option<Arc<crate::control::nfqueue::PendingUdpVerdicts>>,
    pub(in crate::control) tcp_sniff_neg_cache: Arc<crate::control::tcp_sniff::TcpSniffNegCache>,
    pub(in crate::control) sniffer_pool: Arc<crate::control::packet_sniffer::PacketSnifferPool>,
    pub(in crate::control) dns_controller: Arc<crate::control::dns_control::DnsController>,
    pub(in crate::control) alive_set: Arc<AliveDialerSet>,
    pub(in crate::control) connection_pool: Arc<ConnectionPool>,
    pub(in crate::control) connection_tracker: Arc<ConnectionTracker>,
    pub(in crate::control) tcp_flow_pins: Arc<TcpFlowPins>,
    /// Shared clash mode state (None when the clash API is disabled).
    pub(in crate::control) mode_state: Option<crate::mode::SharedModeState>,
}
