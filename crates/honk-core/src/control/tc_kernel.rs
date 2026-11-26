//! TC ownership operations share the policy publication lock across reloads.

use super::connection::handoff::{HandoffResult, TcpFlowGuard, UdpGroupProof};
#[cfg(feature = "native-api")]
use super::connection::observation::ConnectionObservation;
use crate::ebpf::{
    EbpfBackend, FlowExpiryHint, PolicyBackend, RetireCounts, RetireError, RetireOutcome,
    RetireRequest, TcpPin, TcpPinErrorSink, UdpFlowOwner,
};
use honk_ebpf_common::{OutboundIndex, TuplesKey};
use std::os::fd::RawFd;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{RwLock, RwLockReadGuard, mpsc};

mod scan;
pub(super) use scan::MapScan;
#[cfg(test)]
pub(super) use scan::telemetry_sample;

type Policy = Arc<RwLock<Box<dyn PolicyBackend>>>;

pub(super) struct TcKernelController {
    backend: Policy,
}

fn unsupported() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "software policy has no TC capability",
    )
}

impl TcKernelController {
    pub(super) fn share(backend: Box<dyn PolicyBackend>) -> (Policy, Option<Arc<Self>>) {
        let supports_tc = backend.tc().is_ok();
        let backend = Arc::new(RwLock::new(backend));
        let controller = supports_tc.then(|| {
            Arc::new(Self {
                backend: Arc::clone(&backend),
            })
        });
        (backend, controller)
    }

    #[cfg(test)]
    pub(super) fn for_test(backend: Policy) -> Arc<Self> {
        backend
            .try_read()
            .expect("test backend is readable")
            .tc()
            .expect("TC test backend");
        Arc::new(Self { backend })
    }

    pub(super) fn require(controller: &Option<Arc<Self>>) -> anyhow::Result<&Arc<Self>> {
        controller.as_ref().ok_or_else(|| unsupported().into())
    }

    fn map_read(
        guard: RwLockReadGuard<'_, Box<dyn PolicyBackend>>,
    ) -> anyhow::Result<RwLockReadGuard<'_, dyn EbpfBackend + 'static>> {
        RwLockReadGuard::try_map(guard, |backend| backend.tc().ok())
            .map_err(|_| unsupported().into())
    }

    async fn read(&self) -> anyhow::Result<RwLockReadGuard<'_, dyn EbpfBackend + 'static>> {
        Self::map_read(self.backend.read().await)
    }

    fn kernel_mut(
        backend: &mut dyn PolicyBackend,
    ) -> anyhow::Result<&mut (dyn EbpfBackend + 'static)> {
        backend.tc_mut()
    }

    async fn with_write<T>(
        &self,
        operation: impl FnOnce(&mut dyn EbpfBackend) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut guard = self.backend.write().await;
        operation(Self::kernel_mut(guard.as_mut())?)
    }

    pub(super) async fn publish_listeners(
        &self,
        tcp4: RawFd,
        tcp6: Option<RawFd>,
        udp4: &[RawFd],
        udp6: &[RawFd],
    ) -> anyhow::Result<()> {
        self.with_write(|tc| tc.publish_listener_sockets(tcp4, tcp6, udp4, udp6))
            .await
    }

    pub(super) async fn clear_listeners(&self) -> anyhow::Result<()> {
        self.with_write(|tc| tc.clear_listener_sockets()).await
    }

    pub(super) async fn detach_hooks(&self) -> anyhow::Result<()> {
        self.with_write(|tc| tc.detach_hooks()).await
    }

    #[cfg(all(feature = "native-api", feature = "ebpf", target_os = "linux"))]
    pub(super) async fn prepare_receive_trace(
        &self,
    ) -> anyhow::Result<Option<crate::ebpf::real::programs::ReceiveTracePreparation>> {
        Ok(self.read().await?.prepare_receive_trace())
    }

    pub(super) async fn take_expiry_hints(
        &self,
    ) -> anyhow::Result<Option<mpsc::Receiver<FlowExpiryHint>>> {
        self.with_write(|tc| Ok(tc.take_expiry_hints())).await
    }

    pub(super) async fn udp_admission(&self) -> anyhow::Result<UdpAdmission<'_>> {
        Ok(UdpAdmission(self.read().await?))
    }

    /// Read immutable UDP admission metadata without consuming tuple ownership.
    /// The caller carries its original incarnation through deferred admission.
    pub(super) async fn verify_udp_handoff(
        &self,
        tuples: &TuplesKey,
        owner: UdpFlowOwner,
        capture_group: impl FnOnce(u8, u64, u64) -> anyhow::Result<UdpGroupProof>,
        #[cfg(feature = "native-api")] observation: &ConnectionObservation,
        #[cfg(feature = "native-api")] packet_trace_id: Option<u32>,
    ) -> anyhow::Result<(Option<HandoffResult>, Option<UdpGroupProof>)> {
        let backend = self.read().await?;
        let tc = &*backend;
        let (entry, cached_group) = tc.verify_udp_admission(tuples, owner)?;
        let entry = entry.filter(|entry| {
            tuples.dst_port != 53
                || owner.token != 0
                || (entry.result.outbound == OutboundIndex::ControlPlaneRouting as u8
                    && entry.result.must == 0)
        });
        let Some(entry) = entry else {
            // No auxiliary record means no generation proof. Do not manufacture a handoff.
            let group = cached_group
                .map(|slot| capture_group(slot, 0, tc.routing_policy_generation()))
                .transpose()?;
            return Ok((None, group));
        };
        let group = if (OutboundIndex::UserBase as u8..OutboundIndex::MustRules as u8)
            .contains(&entry.result.outbound)
        {
            Some(capture_group(
                entry.result.outbound,
                entry.routing_generation,
                tc.routing_policy_generation(),
            )?)
        } else {
            None
        };
        #[cfg(feature = "native-api")]
        let handoff = HandoffResult::captured(tc, tuples, entry, observation, packet_trace_id);
        #[cfg(not(feature = "native-api"))]
        let handoff = HandoffResult::from(entry);
        Ok((Some(handoff), group))
    }

    /// sock_ops publishes a child's proof after the kernel queued it; measured on x86 the gap is
    /// under 20 us, so a few millisecond-granular retries cover it without delaying a real refusal.
    pub(super) const CHILD_PROOF_RETRIES: u32 = 3;
    const CHILD_PROOF_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(1);

    pub(super) async fn adopt_tcp(
        &self,
        stream: TcpStream,
        tuples: TuplesKey,
        pin_errors: &TcpPinErrorSink,
        install_pin: impl FnOnce(TcpStream, u64, TcpPin) -> TcpFlowGuard,
        #[cfg(feature = "native-api")] observation: &ConnectionObservation,
    ) -> anyhow::Result<(TcpFlowGuard, Option<HandoffResult>)> {
        use std::os::fd::AsFd;
        let mut retries = Self::CHILD_PROOF_RETRIES;
        let (backend, adoption) = loop {
            let backend = self.read().await?;
            match backend.adopt_tcp(stream.as_fd(), &tuples, Arc::clone(pin_errors)) {
                Err(error) if retries > 0 && error.is::<crate::ebpf::TcpChildProofPending>() => {
                    retries -= 1;
                    drop(backend);
                    tokio::time::sleep(Self::CHILD_PROOF_RETRY_DELAY).await;
                }
                result => break (backend, result?),
            }
        };
        // The local pin joins the native pin before releasing backendR.
        let flow = install_pin(stream, adoption.incarnation, adoption.pin);
        #[cfg(feature = "native-api")]
        let handoff = adoption
            .handoff
            .map(|entry| HandoffResult::captured(&*backend, &tuples, entry, observation, None));
        #[cfg(not(feature = "native-api"))]
        let handoff = adoption.handoff.map(HandoffResult::from);
        drop(backend);
        Ok((flow, handoff))
    }
}

/// Retain backendR through the caller's synchronous route capture or pool reservation.
pub(super) struct UdpAdmission<'a>(RwLockReadGuard<'a, dyn EbpfBackend + 'static>);

impl UdpAdmission<'_> {
    pub(super) fn generation(&self) -> u64 {
        self.0.routing_policy_generation()
    }

    pub(super) fn owner(&self, key: &TuplesKey) -> anyhow::Result<UdpFlowOwner> {
        self.0.udp_flow_owner(0, self.0.conn_state_lookup(key)?)
    }

    #[cfg(feature = "native-api")]
    pub(super) fn capture_route(
        &self,
        key: &TuplesKey,
        reference: crate::observe::flows::kernel::KernelRouteReference,
    ) -> Result<crate::observe::flows::kernel::CapturedKernelRoute, &'static str> {
        self.0.capture_kernel_route(key, reference)
    }
}

/// Both retirement paths hold the publication write lock from pin handling
/// through kernel retirement. The caller settles endpoint I/O after return.
impl TcKernelController {
    pub(super) async fn retire_flows(
        &self,
        requests: &mut Vec<RetireRequest<'static>>,
        outcomes: &mut [RetireOutcome],
        prepare: impl FnOnce(&mut Vec<RetireRequest<'static>>),
    ) -> Result<RetireCounts, RetireError> {
        let mut guard = self.backend.write().await;
        prepare(requests);
        outcomes[..requests.len()].fill(RetireOutcome::NotRun);
        Self::retire_locked(guard.as_mut(), requests, outcomes)
    }

    pub(super) fn blocking_retire_unpinned<'a>(
        &self,
        pins: &super::connection::TcpFlowPins,
        candidates: impl Iterator<Item = RetireRequest<'a>>,
        requests: &mut Vec<RetireRequest<'a>>,
        outcomes: &mut [RetireOutcome],
    ) -> Result<RetireCounts, RetireError> {
        let mut guard = self.backend.blocking_write();
        requests.clear();
        requests.extend(candidates.filter(|request| !pins.contains(&request.key)));
        Self::retire_locked(guard.as_mut(), requests, outcomes)
    }

    fn retire_locked(
        backend: &mut dyn PolicyBackend,
        requests: &[RetireRequest<'_>],
        outcomes: &mut [RetireOutcome],
    ) -> Result<RetireCounts, RetireError> {
        if requests.is_empty() {
            return Ok(RetireCounts::default());
        }
        let outcomes = &mut outcomes[..requests.len()];
        Self::kernel_mut(backend)
            .map_err(|source| {
                outcomes.fill(RetireOutcome::NotRun);
                RetireError {
                    counts: Default::default(),
                    source,
                }
            })?
            .retire_batch(requests, outcomes)
    }
}
