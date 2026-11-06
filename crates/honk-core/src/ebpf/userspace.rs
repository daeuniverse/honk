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
impl EbpfBackend for UserspaceBackend {
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

    fn get_bpf_stats(&self, _key: u32) -> anyhow::Result<Option<u64>> {
        Ok(None)
    }
    fn take_expiry_hints(&mut self) -> Option<tokio::sync::mpsc::Receiver<FlowExpiryHint>> {
        None
    }

    fn retire_batch(
        &mut self,
        _requests: &[RetireRequest<'_>],
        outcomes: &mut [RetireOutcome],
    ) -> Result<RetireCounts, RetireError> {
        outcomes.fill(RetireOutcome::NotRun);
        Err(RetireError {
            counts: RetireCounts::default(),
            source: anyhow::anyhow!("XDP has no kernel retirement authority"),
        })
    }
    fn detach_hooks(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support detach_hooks")
    }

    fn attach_dae0_programs(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support attach_dae0_programs")
    }

    fn quiesce_udp_staging(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support quiesce_udp_staging")
    }

    fn attach_dae0peer_ingress(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support attach_dae0peer_ingress")
    }

    fn attach_sk_lookup(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support attach_sk_lookup")
    }

    fn publish_listener_sockets(
        &mut self,
        _tcp4_fd: std::os::unix::io::RawFd,
        _tcp6_fd: Option<std::os::unix::io::RawFd>,
        _udp4_fds: &[std::os::unix::io::RawFd],
        _udp6_fds: &[std::os::unix::io::RawFd],
    ) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support publish_listener_sockets")
    }

    fn clear_listener_sockets(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support clear_listener_sockets")
    }

    #[cfg(feature = "ebpf")]
    fn interface_binding_snapshot(&self) -> anyhow::Result<interface::BindingSnapshot> {
        anyhow::bail!("XDP software policy has no TC interface ownership")
    }

    #[cfg(feature = "ebpf")]
    fn commit_interface_bindings(
        &mut self,
        commit: interface::BindingCommit,
    ) -> Vec<std::os::fd::OwnedFd> {
        if !commit.is_empty() {
            self.admission.store(false, Ordering::Release);
            tracing::error!("TC binding commit reached XDP software policy; closing admission");
        }
        // Even misrouted link FDs must be closed outside the backend lock.
        commit.add.into_iter().map(|(_, _, fd)| fd).collect()
    }

    fn conn_state_lookup(&self, _key: &TuplesKey) -> anyhow::Result<Option<ConnState>> {
        anyhow::bail!("XDP software policy does not support conn_state_lookup")
    }

    fn udp_flow_owner(
        &self,
        _token: u32,
        _state: Option<ConnState>,
    ) -> anyhow::Result<UdpFlowOwner> {
        anyhow::bail!("XDP software policy does not support udp_flow_owner")
    }

    fn commit_udp_decision(
        &mut self,
        _key: &TuplesKey,
        _token: u32,
        _transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        anyhow::bail!("XDP software policy does not support commit_udp_decision")
    }

    fn commit_udp_batch(
        &mut self,
        _requests: &[UdpDecisionCommit],
        _visit: &mut UdpCommitVisit<'_>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support commit_udp_batch")
    }

    fn adopt_tcp(
        &self,
        _fd: std::os::fd::BorrowedFd<'_>,
        _tuples: &TuplesKey,
        _errors: TcpPinErrorSink,
    ) -> anyhow::Result<TcpAdoption> {
        anyhow::bail!("XDP software policy does not support adopt_tcp")
    }

    #[cfg(test)]
    fn tcp_socket_ownership(
        &self,
        _fd: std::os::fd::BorrowedFd<'_>,
    ) -> anyhow::Result<TcpSocketOwnership> {
        anyhow::bail!("XDP software policy does not support tcp_socket_ownership")
    }

    fn verify_udp_decision_sequence(&self) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support verify_udp_decision_sequence")
    }

    fn udp_decision_sequence_status(&self) -> anyhow::Result<UdpDecisionSequenceStatus> {
        anyhow::bail!("XDP software policy does not support udp_decision_sequence_status")
    }

    fn reset_udp_decision_sequence(&mut self, _generation: u32) -> anyhow::Result<bool> {
        anyhow::bail!("XDP software policy does not support reset_udp_decision_sequence")
    }

    fn routing_handoff_lookup(
        &self,
        _key: &TuplesKey,
    ) -> anyhow::Result<Option<RoutingHandoffEntry>> {
        anyhow::bail!("XDP software policy does not support routing_handoff_lookup")
    }

    fn redirect_track_lookup(&self, _key: &RedirectTuple) -> anyhow::Result<Option<RedirectEntry>> {
        anyhow::bail!("XDP software policy does not support redirect_track_lookup")
    }

    fn conn_state_for_each_chunk(
        &self,
        _chunk_size: usize,
        _cursor: &mut FlowScanCursor,
        _visit: &mut ConnStateChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support conn_state_for_each_chunk")
    }

    fn redirect_track_for_each_chunk(
        &self,
        _chunk_size: usize,
        _cursor: &mut FlowScanCursor,
        _visit: &mut RedirectTrackChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support redirect_track_for_each_chunk")
    }

    fn routing_handoff_for_each_chunk(
        &self,
        _chunk_size: usize,
        _cursor: &mut FlowScanCursor,
        _visit: &mut RoutingHandoffChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support routing_handoff_for_each_chunk")
    }

    fn set_admission_pressure(&mut self, _pressured: bool) -> anyhow::Result<()> {
        anyhow::bail!("XDP software policy does not support set_admission_pressure")
    }

    fn conn_state_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        anyhow::bail!("XDP software policy does not support conn_state_occupancy")
    }

    fn aux_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        anyhow::bail!("XDP software policy does not support aux_occupancy")
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
        assert_eq!(backend.get_bpf_stats(0).unwrap(), None);
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
        assert!(backend.attach_dae0_programs().is_err());
        assert!(
            backend
                .publish_listener_sockets(-1, None, &[], &[])
                .is_err()
        );
        assert!(backend.verify_udp_decision_sequence().is_err());
        assert!(backend.udp_flow_owner(0, None).is_err());
        assert!(backend.quiesce_udp_staging().is_err());
        backend.cleanup().await.unwrap();
        assert!(!admission.load(Ordering::Acquire));
        assert!(backend.policy.routing_generation.is_none());
        assert!(!backend.get_outbound_alive(2, 0, 0).unwrap());
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn unexpected_tc_commit_fences_admission_and_defers_descriptor_disposal() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        let admission = Arc::new(AtomicBool::new(false));
        let mut backend = UserspaceBackend::new(Arc::clone(&admission));
        assert!(backend.interface_binding_snapshot().is_err());
        admission.store(true, Ordering::Release);
        let (owned, mut peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let closed = backend.commit_interface_bindings(interface::BindingCommit {
            add: vec![(
                interface::Binding {
                    ifindex: std::num::NonZeroU32::new(1).unwrap(),
                    direction: interface::Direction::Ingress,
                    program: interface::TcProgram::LanIngressL2,
                    interface: "test".into(),
                },
                1,
                owned.into(),
            )],
            ..Default::default()
        });
        assert!(!admission.load(Ordering::Acquire));
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(closed);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}
