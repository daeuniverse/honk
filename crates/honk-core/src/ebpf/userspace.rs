//! Software policy publication for packet backends; capture ownership stays with their runtime.

use super::policy_state::PolicyState;
use super::*;
#[cfg(feature = "ebpf")]
use anyhow::Context;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub struct UserspaceBackend {
    policy: PolicyState,
    admission: Arc<AtomicBool>,
    pname_support: PnameSupportCell,
    flags: u32,
    routing_plan: Option<crate::control::routing_matcher::RoutingPushPlan>,
    #[cfg(feature = "ebpf")]
    native: Option<Arc<super::native::NativePublication>>,
}

impl UserspaceBackend {
    pub fn new(admission: Arc<AtomicBool>, pname_support: PnameSupportCell) -> Self {
        admission.store(false, Ordering::Release);
        *pname_support.write() = PnameSupport::Unavailable;
        Self {
            policy: PolicyState::default(),
            admission,
            pname_support,
            flags: 0,
            routing_plan: None,
            #[cfg(feature = "ebpf")]
            native: None,
        }
    }
    }

    #[cfg(feature = "ebpf")]
    pub fn native_publication(&self) -> Option<Arc<super::native::NativePublication>> {
        self.native.clone()
    }

    #[cfg(feature = "ebpf")]
    pub fn install_native_publication(
        &mut self,
        publication: Arc<super::native::NativePublication>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.native.is_none(),
            "native publication already installed"
        );
        let writer = publication.write(super::native::NativeReason::Startup)?;
        publication.set_flags(self.flags)?;
        if let Some(plan) = &self.routing_plan {
            publication.publish_plan(plan, &writer)?;
        }
        publication.set_ready(self.admission.load(Ordering::Acquire))?;
        self.native = Some(publication);
        writer.commit();
        Ok(())
}

#[async_trait]
impl PolicyBackend for UserspaceBackend {
    #[cfg(feature = "ebpf")]
    fn native_publication(&self) -> Option<Arc<super::native::NativePublication>> {
        UserspaceBackend::native_publication(self)
    }

    #[cfg(feature = "ebpf")]
    fn install_native_publication(
        &mut self,
        publication: Arc<super::native::NativePublication>,
    ) -> anyhow::Result<()> {
        UserspaceBackend::install_native_publication(self, publication)
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
        #[cfg(feature = "ebpf")]
        let native = self.native.clone();
        #[cfg(feature = "ebpf")]
        let writer = native
            .as_ref()
            .map(|publication| {
                let preparation = publication.preflight_host_plan(plan)?;
                publication.write_prepared_plan(super::native::NativeReason::Policy, preparation)
            })
            .transpose()?;
        self.policy.publish(plan, learned_domains, |phase, _| {
            #[cfg(feature = "ebpf")]
            if phase == RoutingPushPhase::Root
                && let Some(publication) = &native
            {
                publication.publish_plan(
                    plan,
                    writer
                        .as_ref()
                        .context("native policy publication requires its initiating writer")?,
                )?;
            }
            #[cfg(not(feature = "ebpf"))]
            let _ = phase;
            Ok(())
        })?;
        self.routing_plan = Some(plan.clone());
        #[cfg(feature = "ebpf")]
        if let Some(writer) = writer {
            writer.commit();
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
            "packet software policy cannot enable NFQUEUE or kernel route witnesses"
        );
        #[cfg(feature = "ebpf")]
        if let Some(publication) = &self.native {
            publication.set_flags(flags)?;
        }
        self.flags = flags;
        Ok(())
    }

    fn set_datapath_ready(&mut self, ready: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            !ready || self.policy.routing_generation.is_some(),
            "no published software policy"
        );
        #[cfg(feature = "ebpf")]
        if let Some(publication) = &self.native {
            publication.set_ready(ready)?;
        }
        self.admission.store(ready, Ordering::Release);
        Ok(())
    }

    async fn cleanup(&mut self) -> anyhow::Result<()> {
        self.admission.store(false, Ordering::Release);
        #[cfg(feature = "ebpf")]
        if let Some(publication) = &self.native {
            publication.quiesce(super::native::NativeReason::Shutdown)?;
        }
        *self.pname_support.write() = PnameSupport::Unavailable;
        self.policy.clear();
        self.routing_plan = None;
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

    #[cfg(feature = "ebpf")]
    #[tokio::test]
    async fn native_userspace_install_policy_and_cleanup_keep_actual_reasons() {
        use super::super::native::{NativePublication, NativeReason};
        use honk_ebpf_common::xdp::{NATIVE_EVENT_TERMINAL_STATE, NATIVE_EVENT_WRITER_BEGIN};
        let admission = Arc::new(AtomicBool::new(false));
        let support = Arc::new(parking_lot::RwLock::new(PnameSupport::Unavailable));
        let mut backend = UserspaceBackend::new(admission, support);
        backend.publish_routing_plan(&plan(), &[]).unwrap();
        let publication =
            NativePublication::recording_for_test(honk_netstack::MemoryBudget::new(2 << 20))
                .unwrap();
        let maintenance = publication.write(NativeReason::RuntimeMaintenance).unwrap();
        let maintenance_id = maintenance.writer_id_for_test();
        backend
            .install_native_publication(Arc::clone(&publication))
            .unwrap();
        backend.publish_routing_plan(&plan(), &[]).unwrap();
        let events = publication.recording_events_for_test();
        assert!(events.len() < 32);
        assert_eq!(events.first().unwrap().seq, 1);
        for reason in [
            NativeReason::Startup,
            NativeReason::Flags,
            NativeReason::Ready,
            NativeReason::Policy,
        ] {
            assert!(
                events
                    .iter()
                    .any(|event| event.kind == NATIVE_EVENT_WRITER_BEGIN
                        && event.reason == reason as u32),
                "missing actual writer reason {reason:?}"
            );
        }
        let startup_id = events
            .iter()
            .find(|event| {
                event.kind == NATIVE_EVENT_WRITER_BEGIN
                    && event.reason == NativeReason::Startup as u32
            })
            .unwrap()
            .writer_id;
        let policy = events
            .iter()
            .filter(|event| {
                event.kind == NATIVE_EVENT_WRITER_BEGIN
                    && event.reason == NativeReason::Policy as u32
            })
            .collect::<Vec<_>>();
        assert_eq!(policy.first().unwrap().writer_id, startup_id);
        assert!(policy.iter().all(|event| event.writer_id != maintenance_id));
        maintenance.commit();
        backend.cleanup().await.unwrap();
        let events = publication.recording_events_for_test();
        assert!(
            events
                .iter()
                .any(|event| event.kind == NATIVE_EVENT_TERMINAL_STATE
                    && event.reason == NativeReason::Shutdown as u32)
        );
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
        assert!(backend.tc().is_err());
        assert!(backend.tc_mut().is_err());
        backend.cleanup().await.unwrap();
        assert!(!admission.load(Ordering::Acquire));
        assert_eq!(backend.pname_support(), PnameSupport::Unavailable);
        assert!(backend.policy.routing_generation.is_none());
        assert!(!backend.get_outbound_alive(2, 0, 0).unwrap());
    }
}
