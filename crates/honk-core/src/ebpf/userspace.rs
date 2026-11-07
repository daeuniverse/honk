//! Software policy publication for the XDP runtime; capture ownership stays with that runtime.

use super::policy_state::PolicyState;
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub struct UserspaceBackend {
    policy: PolicyState,
    admission: Arc<AtomicBool>,
    flags: u32,
}

impl UserspaceBackend {
    pub fn new(admission: Arc<AtomicBool>) -> Self {
        admission.store(false, Ordering::Release);
        Self {
            policy: PolicyState::default(),
            admission,
            flags: 0,
        }
    }
}

#[async_trait]
impl PolicyBackend for UserspaceBackend {
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
        let mut result = DatapathObservation::unknown(DatapathKind::XdpUserspace);
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
        PnameSupport::Unavailable
    }

    fn publish_routing_plan(
        &mut self,
        plan: &crate::control::routing_matcher::RoutingPushPlan,
        learned_domains: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()> {
        self.policy.publish(plan, learned_domains, |_, _| Ok(()))
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

    fn set_datapath_flags(&mut self, flags: u32) -> anyhow::Result<()> {
        anyhow::ensure!(
            flags
                & (DATAPATH_FLAG_NFQ_ENABLED
                    | DATAPATH_FLAG_NFQ_READY
                    | DATAPATH_FLAG_TRACE_ENABLED)
                == 0,
            "XDP software policy cannot enable NFQUEUE or kernel route witnesses"
        );
        self.flags = flags;
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
        let mut backend = UserspaceBackend::new(Arc::clone(&admission));
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
        assert_eq!(observed.kind, DatapathKind::XdpUserspace);
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
        assert!(backend.tc().is_err());
        assert!(backend.tc_mut().is_err());
        backend.cleanup().await.unwrap();
        assert!(!admission.load(Ordering::Acquire));
        assert!(backend.policy.routing_generation.is_none());
        assert!(!backend.get_outbound_alive(2, 0, 0).unwrap());
    }
}
