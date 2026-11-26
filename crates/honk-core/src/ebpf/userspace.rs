//! Software policy publication for packet backends; capture ownership stays with their runtime.

use super::policy_state::PolicyState;
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[cfg(target_os = "linux")]
#[derive(PartialEq, Eq)]
enum GatewayDnsReload {
    Initial,
    Pending(u64),
    Ready(u64),
    Degraded,
    Closed,
}

pub struct UserspaceBackend {
    policy: PolicyState,
    admission: Arc<AtomicBool>,
    pname_support: PnameSupportCell,
    mode_flags: u32,
    #[cfg(target_os = "linux")]
    gateway: Option<Arc<GatewayPublisher>>,
    #[cfg(target_os = "linux")]
    gateway_capture_started: bool,
    #[cfg(target_os = "linux")]
    gateway_dns_reload: GatewayDnsReload,
    #[cfg(target_os = "linux")]
    auxiliary_fenced: bool,
}

impl UserspaceBackend {
    pub fn new(admission: Arc<AtomicBool>, pname_support: PnameSupportCell) -> Self {
        admission.store(false, Ordering::Release);
        *pname_support.write() = PnameSupport::Unavailable;
        Self {
            policy: PolicyState::default(),
            admission,
            pname_support,
            mode_flags: 0,
            #[cfg(target_os = "linux")]
            gateway: None,
            #[cfg(target_os = "linux")]
            gateway_capture_started: false,
            #[cfg(target_os = "linux")]
            gateway_dns_reload: GatewayDnsReload::Initial,
            #[cfg(target_os = "linux")]
            auxiliary_fenced: false,
        }
    }

    #[cfg(all(target_os = "linux", test, feature = "ebpf"))]
    pub(crate) fn gateway(&self) -> Option<&Arc<GatewayPublisher>> {
        self.gateway.as_ref()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn pause_gateway_auxiliary(&mut self) {
        self.auxiliary_fenced = true;
        if let Some(publisher) = &self.gateway {
            publisher.pause_auxiliary();
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn restore_gateway_auxiliary(&mut self) -> std::io::Result<()> {
        if self.auxiliary_fenced
            && let Some(publisher) = &self.gateway
        {
            publisher.restore_auxiliary()?;
        }
        self.auxiliary_fenced = false;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn verify_gateway_auxiliary(
        &self,
        fingerprint: [u8; 32],
        generation: u64,
    ) -> std::io::Result<()> {
        if self.auxiliary_fenced
            || matches!(
                self.gateway_dns_reload,
                GatewayDnsReload::Pending(_)
                    | GatewayDnsReload::Degraded
                    | GatewayDnsReload::Closed
            )
        {
            return Err(std::io::Error::other("gateway publication is not ready"));
        }
        if self.gateway_capture_started
            && let Some(publisher) = &self.gateway
        {
            publisher.verify_committed(fingerprint, generation)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn stage_gateway_dns_reload(&mut self, generation: u64) {
        // Capture can register after canonical commit releases the backend lock.
        if self.gateway_dns_reload != GatewayDnsReload::Closed {
            self.gateway_dns_reload = GatewayDnsReload::Pending(generation);
            if let Some(publisher) = &self.gateway {
                publisher.stage_dns_reload();
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn finish_gateway_dns_reload(
        &mut self,
        generation: u64,
        fingerprint: [u8; 32],
    ) -> std::io::Result<bool> {
        if self.gateway_dns_reload != GatewayDnsReload::Pending(generation) {
            return Ok(false);
        }
        self.restore_gateway_auxiliary()?;
        if self.gateway_capture_started
            && let Some(publisher) = &self.gateway
        {
            publisher.activate_dns(fingerprint, generation, true)?;
        }
        self.gateway_dns_reload = GatewayDnsReload::Ready(generation);
        Ok(true)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn degrade_gateway_dns(&mut self) {
        if self.gateway_dns_reload != GatewayDnsReload::Closed {
            self.gateway_dns_reload = GatewayDnsReload::Degraded;
            if let Some(publisher) = &self.gateway {
                publisher.degrade_dns();
            }
        }
    }
}

impl DomainProjectionSink for UserspaceBackend {
    fn set_domain_ip_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> Result<(), DomainRouteWriteError> {
        self.policy.set_domain(key, bitmap)
    }
    fn remove_domain_ip_bitmap(&mut self, key: &LpmKey) -> Result<(), DomainRouteWriteError> {
        self.policy.remove_domain(key)
    }
}

#[async_trait]
impl PolicyBackend for UserspaceBackend {
    fn userspace_mut(&mut self) -> anyhow::Result<&mut UserspaceBackend> {
        Ok(self)
    }

    #[cfg(target_os = "linux")]
    fn install_gateway(&mut self, gateway: Option<Arc<GatewayPublisher>>) -> anyhow::Result<()> {
        if let Some(publisher) = &gateway {
            anyhow::ensure!(
                self.gateway_dns_reload != GatewayDnsReload::Closed,
                "userspace backend is closed"
            );
            publisher.set_mode_flags(self.mode_flags)?;
            if self.auxiliary_fenced {
                publisher.pause_auxiliary();
            }
        }
        if let Some(previous) = &self.gateway
            && gateway
                .as_ref()
                .is_none_or(|next| !Arc::ptr_eq(previous, next))
        {
            previous.stop_dns();
            self.gateway_capture_started = false;
        }
        if self.gateway_dns_reload == GatewayDnsReload::Degraded
            && let Some(publisher) = &gateway
        {
            publisher.degrade_dns();
        }
        self.gateway = gateway;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn activate_gateway_start(
        &mut self,
        publisher: &Arc<GatewayPublisher>,
        fingerprint: [u8; 32],
        generation: u64,
    ) -> std::io::Result<()> {
        if self.gateway_capture_started
            || self
                .gateway
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, publisher))
        {
            return Ok(());
        }
        match self.gateway_dns_reload {
            GatewayDnsReload::Pending(current) | GatewayDnsReload::Ready(current)
                if current != generation =>
            {
                return Ok(());
            }
            GatewayDnsReload::Closed => return Ok(()),
            _ => {}
        }
        if matches!(self.gateway_dns_reload, GatewayDnsReload::Initial)
            || self.gateway_dns_reload == GatewayDnsReload::Ready(generation)
        {
            publisher.activate_dns(fingerprint, generation, false)?;
        }
        self.gateway_capture_started = true;
        Ok(())
    }

    fn tc(&self) -> anyhow::Result<&(dyn EbpfBackend + 'static)> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "software policy has no TC capability",
        )
        .into())
    }

    fn tc_mut(&mut self) -> anyhow::Result<&mut (dyn EbpfBackend + 'static)> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "software policy has no TC capability",
        )
        .into())
    }

    fn observe_datapath(&self) -> DatapathObservation {
        let mut result = DatapathObservation::unknown(DatapathKind::PacketUserspace);
        result.routing = if self.policy.routing_generation.is_some() {
            DatapathCheck::Verified
        } else {
            DatapathCheck::Absent
        };
        result.routing_generation = self
            .policy
            .routing_generation
            .as_ref()
            .map(|_| self.policy.next_generation);
        result.admission = Some(self.admission.load(Ordering::Acquire));
        result
    }

    fn pname_support(&self) -> PnameSupport {
        *self.pname_support.read()
    }

    fn publish_routing_plan(
        &mut self,
        plan: &crate::control::routing_matcher::RoutingPushPlan,
        learned_domains: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(gateway) = &self.gateway {
            gateway.publish(plan)?;
        }
        if let Err(error) = self.policy.publish(plan, learned_domains, |_, _| Ok(())) {
            #[cfg(target_os = "linux")]
            if let Some(gateway) = &self.gateway
                && let Err(rollback_error) = gateway.rollback()
            {
                return Err(anyhow::anyhow!(
                    "software policy publication failed: {error}; gateway rollback failed: {rollback_error}"
                ));
            }
            return Err(error);
        }
        #[cfg(target_os = "linux")]
        if let Some(gateway) = &self.gateway {
            gateway.commit();
        }
        Ok(())
    }

    fn routing_policy_generation(&self) -> u64 {
        self.policy.next_generation
    }
    fn active_routing_slot(&self) -> anyhow::Result<u32> {
        Ok(self.policy.active_slot)
    }

    fn add_domain_ip_bitmap(&mut self, key: &LpmKey, bitmap: &DomainRouting) -> anyhow::Result<()> {
        self.policy.add_domain(key, bitmap)
    }
    fn set_outbound_alive(
        &mut self,
        outbound: u8,
        domain: u32,
        ipver: u32,
        alive: bool,
    ) -> anyhow::Result<()> {
        self.policy.set_alive(outbound, domain, ipver, alive);
        Ok(())
    }
    fn get_outbound_alive(&self, outbound: u8, domain: u32, ipver: u32) -> anyhow::Result<bool> {
        Ok(self.policy.alive(outbound, domain, ipver))
    }

    fn mode_flags(&self) -> std::io::Result<u32> {
        Ok(self.mode_flags)
    }

    fn set_datapath_flags(&mut self, flags: u32) -> anyhow::Result<()> {
        anyhow::ensure!(
            flags
                & (DATAPATH_FLAG_NFQ_ENABLED
                    | DATAPATH_FLAG_NFQ_READY
                    | DATAPATH_FLAG_TRACE_ENABLED)
                == 0,
            "packet software policy cannot enable NFQUEUE or kernel route witnesses"
        );
        #[cfg(target_os = "linux")]
        if let Some(gateway) = &self.gateway {
            gateway.set_mode_flags(flags)?;
        }
        self.mode_flags = flags;
        Ok(())
    }

    fn set_datapath_ready(&mut self, ready: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            !ready || self.policy.routing_generation.is_some(),
            "no published software policy"
        );
        self.admission.store(ready, Ordering::Release);
        Ok(())
    }

    async fn cleanup(&mut self) -> anyhow::Result<()> {
        self.admission.store(false, Ordering::Release);
        #[cfg(target_os = "linux")]
        {
            self.gateway_dns_reload = GatewayDnsReload::Closed;
            self.gateway_capture_started = false;
            if let Some(gateway) = self.gateway.take() {
                gateway.stop_dns();
            }
        }
        *self.pname_support.write() = PnameSupport::Unavailable;
        self.policy.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> crate::control::routing_matcher::RoutingPushPlan {
        let router = crate::routing::Router::new(&[], "direct").unwrap();
        crate::control::routing_matcher::RoutingPushPlan::compile(
            &router,
            &std::collections::HashMap::from([("direct".into(), 0)]),
            honk_config::types::DialMode::Domain,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn software_publication_preserves_policy_on_failure_and_closes_real_admission() {
        let admission = Arc::new(AtomicBool::new(false));
        let support = Arc::new(parking_lot::RwLock::new(PnameSupport::Unavailable));
        let mut backend = UserspaceBackend::new(Arc::clone(&admission), Arc::clone(&support));
        assert_eq!(backend.pname_support(), PnameSupport::Unavailable);
        for mode in [
            PnameSupport::HostFull,
            PnameSupport::HostThreadName,
            PnameSupport::Unavailable,
        ] {
            *support.write() = mode;
            assert_eq!(backend.pname_support(), mode);
        }
        *support.write() = PnameSupport::HostThreadName;
        assert!(backend.set_datapath_ready(true).is_err());
        let plan = plan();
        let key = LpmKey {
            prefix_len: 128,
            data: [1, 2, 3, 4],
        };
        let mut bitmap = DomainRouting::default();
        bitmap.bitmap[0] = 1;
        backend
            .publish_routing_plan(&plan, &[(key, bitmap)])
            .unwrap();
        backend.set_outbound_alive(2, 0, 0, true).unwrap();
        assert!(backend.get_outbound_alive(2, 0, 0).unwrap());
        backend
            .set_datapath_flags(DATAPATH_FLAG_OFFLOAD_ALL)
            .unwrap();
        backend.set_datapath_ready(true).unwrap();
        assert!(admission.load(Ordering::Acquire));
        let generation = backend.routing_policy_generation();
        let descriptor = backend.policy.descriptor;
        assert!(
            backend
                .policy
                .publish(&plan, &[], |phase, _| {
                    anyhow::ensure!(phase != RoutingPushPhase::Root, "publication failure");
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(backend.policy.descriptor, descriptor);
        assert_eq!(backend.routing_policy_generation(), generation);
        assert_eq!(
            backend.policy.routing_generation.as_ref().unwrap().domain[&key.data].bitmap[0],
            1
        );
        backend
            .set_domain_ip_bitmap(&key, &DomainRouting::default())
            .unwrap();
        assert!(
            backend
                .policy
                .routing_generation
                .as_ref()
                .unwrap()
                .domain
                .contains_key(&key.data)
        );
        backend.remove_domain_ip_bitmap(&key).unwrap();
        assert!(
            backend
                .policy
                .routing_generation
                .as_ref()
                .unwrap()
                .domain
                .is_empty()
        );
        backend.add_domain_ip_bitmap(&key, &bitmap).unwrap();
        bitmap.bitmap[0] = 2;
        backend.add_domain_ip_bitmap(&key, &bitmap).unwrap();
        assert_eq!(
            backend.policy.routing_generation.as_ref().unwrap().domain[&key.data].bitmap[0],
            3
        );
        let observed = backend.observe_datapath();
        assert_eq!(observed.kind, DatapathKind::PacketUserspace);
        assert_eq!(observed.programs, DatapathCheck::Unknown);
        assert_eq!(observed.hooks, DatapathCheck::Unknown);
        assert_eq!(observed.conn_state_capacity, None);
        assert!(
            backend
                .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED)
                .is_err()
        );
        assert!(
            backend
                .set_datapath_flags(DATAPATH_FLAG_TRACE_ENABLED)
                .is_err()
        );
        assert_eq!(backend.mode_flags().unwrap(), DATAPATH_FLAG_OFFLOAD_ALL);
        assert!(backend.tc().is_err());
        assert!(backend.tc_mut().is_err());
        backend.cleanup().await.unwrap();
        assert!(!admission.load(Ordering::Acquire));
        assert_eq!(backend.pname_support(), PnameSupport::Unavailable);
        assert!(backend.policy.routing_generation.is_none());
        assert!(!backend.get_outbound_alive(2, 0, 0).unwrap());
    }
}
