use honk_xsk::{GatewayArbitration, GatewayMaps};
use std::io;
use std::net::{IpAddr, Ipv6Addr};
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
        arbitration: Option<&GatewayArbitration>,
        retains: &mut dyn FnMut(u32, IpAddr) -> bool,
    ) -> io::Result<usize> {
        maps.retire_if_unretained(now_ns, HOLD_IDLE, arbitration, |key| {
            retains(
                key.realm_id,
                IpAddr::V6(Ipv6Addr::from(key.src)).to_canonical(),
            )
        })
    }
}
