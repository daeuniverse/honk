//! Accepted-child ownership proof attachment and FD storage access.

use std::os::fd::BorrowedFd;

use anyhow::{Context, Result, anyhow, ensure};
use aya::{
    Ebpf,
    maps::SkStorage,
    programs::{CgroupAttachMode, SockOps, sock_ops::SockOpsLink},
};
use honk_ebpf_common::redirect_need::TcpSocketBinding;

/// An exact native lifetime pin; clones only the backend's shared map handle.
pub struct TcpKernelPin {
    map: std::sync::Arc<aya::maps::MapData>,
    incarnation: Option<u64>,
    errors: crate::ebpf::TcpPinErrorSink,
}

impl TcpKernelPin {
    pub(super) fn retain(
        map: &std::sync::Arc<aya::maps::MapData>,
        incarnation: u64,
        errors: crate::ebpf::TcpPinErrorSink,
    ) -> Result<Self> {
        ensure!(
            incarnation != 0 && incarnation <= honk_ebpf_common::conn::FLOW_INCARNATION_MAX,
            "invalid TCP lifetime identity"
        );
        super::syscall::insert_tcp_live_pin(map, incarnation)?;
        Ok(Self {
            map: std::sync::Arc::clone(map),
            incarnation: Some(incarnation),
            errors,
        })
    }

    fn release_once(&mut self) -> Result<()> {
        if let Some(incarnation) = self.incarnation.take() {
            super::syscall::remove_tcp_live_pin(&self.map, incarnation)?;
        }
        Ok(())
    }

    pub fn release(mut self) -> Result<()> {
        self.release_once()
    }
}

impl Drop for TcpKernelPin {
    fn drop(&mut self) {
        if let Err(error) = self.release_once() {
            let sink = self.errors.lock();
            match sink.as_ref() {
                Some(sender) => {
                    if let Err(error) = sender.send(error) {
                        tracing::error!(error = %error.0, "TCP pin release error channel closed");
                    }
                }
                None => tracing::error!(%error, "TCP pin release error channel unavailable"),
            }
        }
    }
}

pub(super) fn take_live_pins(bpf: &mut Ebpf) -> Result<std::sync::Arc<aya::maps::MapData>> {
    match bpf.take_map("TCP_LIVE_PINS") {
        Some(aya::maps::Map::HashMap(map)) => Ok(std::sync::Arc::new(map)),
        _ => anyhow::bail!("TCP_LIVE_PINS unavailable or has an incompatible map type"),
    }
}

/// Attach the child-proof program to the root cgroup. aya links are `BPF_LINK_CREATE`
/// (always multi-attach): they coexist with each other, and only a legacy flags=0 program
/// already at the cgroup refuses the link.
pub(super) fn attach(bpf: &mut Ebpf, cgroup: &std::fs::File) -> Result<SockOpsLink> {
    let program: &mut SockOps = bpf
        .program_mut("honk_tcp_passive")
        .ok_or_else(|| anyhow!("required TCP child proof program missing"))?
        .try_into()?;
    program.load().context("loading required TCP child proof")?;
    let link = program.attach(cgroup, CgroupAttachMode::Single).context(
        "attaching required TCP child proof: the root cgroup sock_ops slot may be held by \
             a legacy (flags=0) program",
    )?;
    Ok(program.take_link(link)?)
}

pub(super) fn lookup(
    bpf: &super::programs::KernelMaps,
    fd: BorrowedFd<'_>,
) -> Result<TcpSocketBinding> {
    let storage = SkStorage::<_, TcpSocketBinding>::try_from(
        bpf.get("TCP_SOCKET_BINDING")
            .ok_or_else(|| anyhow!("required TCP_SOCKET_BINDING missing"))?,
    )?;
    match storage.get(&fd, 0) {
        Ok(binding) => Ok(binding),
        Err(aya::maps::MapError::KeyNotFound) => Err(crate::ebpf::TcpChildProofPending.into()),
        Err(error) => Err(anyhow::Error::new(error).context("reading accepted socket ownership")),
    }
}

pub(super) fn adopt(
    backend: &super::RealEbpfBackend,
    fd: BorrowedFd<'_>,
    tuples: &honk_ebpf_common::TuplesKey,
    errors: crate::ebpf::TcpPinErrorSink,
) -> Result<crate::ebpf::TcpAdoption> {
    use crate::ebpf::EbpfBackend;
    ensure!(
        !backend.retirement_failed,
        "retirement ownership is unresolved"
    );
    let binding = lookup(backend.maps()?, fd)?;
    let current = backend
        .conn_state_lookup(tuples)?
        .ok_or_else(|| anyhow!("accepted TCP flow has no conn-state: {tuples:?}"))?;
    ensure!(
        binding.kind == honk_ebpf_common::redirect_need::TCP_BINDING_CHILD
            && crate::ebpf::tuple_matches(&binding.tuples, tuples)
            && binding.handoff.incarnation != 0
            && binding.handoff.incarnation == current.incarnation,
        "accepted TCP child is unproven or superseded"
    );
    let handoff = backend
        .routing_handoff_lookup(tuples)?
        .ok_or_else(|| anyhow!("accepted TCP child has no current handoff"))?;
    let redirect = backend
        .redirect_track_lookup(&honk_ebpf_common::RedirectTuple::from_tuples(tuples))?
        .ok_or_else(|| anyhow!("accepted TCP child has no current redirect"))?;
    ensure!(
        handoff.incarnation == current.incarnation && redirect.incarnation == current.incarnation,
        "accepted TCP child auxiliary ownership is superseded"
    );
    Ok(crate::ebpf::TcpAdoption {
        incarnation: current.incarnation,
        handoff: Some(binding.handoff),
        pin: crate::ebpf::TcpPin::Kernel(TcpKernelPin::retain(
            &backend.tcp_live_pins,
            current.incarnation,
            errors,
        )?),
    })
}
