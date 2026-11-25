use honk_ebpf_common::xdp_gateway::GatewayKey;
use honk_netstack::MemoryBudget;
use honk_xsk::{GatewayArbitration, GatewayMaps};
use std::io;
use std::sync::Arc;
use std::time::Duration;

pub(crate) const HOLD_IDLE: Duration = Duration::from_secs(30);
pub(crate) const HOLD_REFRESH: Duration = Duration::from_secs(1);

const _: () = {
    assert!(HOLD_IDLE.as_nanos() == honk_ebpf_common::xdp_gateway::HOLD_IDLE_NS as u128);
    assert!(HOLD_REFRESH.as_nanos() == honk_ebpf_common::xdp_gateway::HOLD_REFRESH_NS as u128);
};

#[derive(Default)]
pub(crate) struct HoldCollector;

impl HoldCollector {
    /// Run outside receive callbacks, which already hold the endpoint scope mutex.
    pub(crate) fn sweep(
        &mut self,
        maps: &GatewayMaps,
        now_ns: u64,
        lan_arbitration: Option<&GatewayArbitration>,
        host_arbitration: Option<&GatewayArbitration>,
        budget: &Arc<MemoryBudget>,
        retains: &mut dyn FnMut(&GatewayKey) -> bool,
    ) -> io::Result<usize> {
        let mut removed =
            maps.retire_if_unretained(now_ns, HOLD_IDLE, lan_arbitration, &mut *retains)?;
        if let Some(arbitration) = host_arbitration {
            removed += maps.retire_host_flows(now_ns, arbitration, budget, retains)?;
            maps.request_host_drain(arbitration, now_ns)?;
        }
        Ok(removed)
    }
}
