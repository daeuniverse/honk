use async_trait::async_trait;
use aya::maps::lpm_trie::Key as AyaLpmKey;
use aya::maps::{
    Array as AyaArray, HashMap as AyaHashMap, LpmTrie as AyaLpmTrie, MapData as AyaMapData,
    MapError, PerCpuArray as AyaPerCpuArray, SockMap as AyaSockMap,
};
use aya::{Ebpf, EbpfLoader, Pod};

use honk_ebpf_common::*;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

#[cfg(test)]
use super::TcpSocketOwnership;
use super::retirement::AuxDeleteTally;
use super::{
    EbpfBackend, FlowExpiryHint, RETIRE_BATCH_CAPACITY, RETIRE_FENCE_MAP, RetireCounts,
    RetireError, RetireKind, RetireOutcome, RetireRequest, UDP_DECISION_SEQUENCE_MAP,
    UdpDecisionCommitResult, UdpDecisionSequenceStatus, UdpDecisionTransition,
    probe::BatchCapability, validate_udp_decision_transition,
};

/// Parse the running kernel version from /proc/version.
/// Returns `(major, minor, patch)` on success; `patch` defaults to 0
/// if the version string only carries two components.
fn kernel_version() -> Option<(u32, u32, u32)> {
    let version = std::fs::read_to_string("/proc/version").ok()?;
    let ver_str = version.split_whitespace().nth(2)?;
    let parts: Vec<&str> = ver_str.split('.').collect();
    if parts.len() >= 2 {
        let major = parts[0].parse::<u32>().ok()?;
        let minor = parts[1].parse::<u32>().ok()?;
        let patch = parts
            .get(2)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        Some((major, minor, patch))
    } else {
        None
    }
}

/// Real eBPF backend backed by Aya and kernel BPF maps.
///
/// Aya owns ordinary map operations; raw extensions provide batch reads/writes
/// and locked persistent-allocator access. Every reclamation uses fence/grace.
pub struct RealEbpfBackend {
    bpf: Option<Ebpf>,
    pin_root: PathBuf,
    /// Map names this instance claimed at attach, so cleanup unlinks what it owns instead of
    /// everything under a pin root that is shared with every other BPF consumer.
    pinned_maps: Vec<String>,
    /// Every TCX link on a configured interface, keyed by `(ifindex, direction)`,
    /// plus the preloaded TC program FDs. Created and replaced only through
    /// `bindings::apply`; dropped by `detach_hooks`.
    bindings: bindings::InterfaceBindings,
    /// cgroup sock_create identity-capture link, held for the backend lifetime.
    /// Dropping the link detaches the program in the kernel.
    cgroup_sock_links: Vec<aya::programs::cgroup_sock::CgroupSockLink>,
    /// cgroup connect4/6 + sendmsg4/6 links; same lifetime rule as above.
    cgroup_sock_addr_links: Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>,
    pname_mode: process_name::PnameCaptureMode,
    dae0_ingress_link: Option<aya::programs::tc::SchedClassifierLink>,
    dae0peer_ingress_link: Option<aya::programs::tc::SchedClassifierLink>,
    sk_lookup_link: Option<aya::programs::sk_lookup::SkLookupLink>,
    listeners_published: bool,
    /// Background task that flushes aya-log ring-buffer records.
    log_flush_handle: Option<tokio::task::JoinHandle<()>>,
    /// Background task that drains EVENT_RINGBUF (DaeEvent) into the log.
    event_flush_handle: Option<tokio::task::JoinHandle<()>>,
    expiry_hints: Option<tokio::sync::mpsc::Receiver<FlowExpiryHint>>,
    retirement_grace_inner: AyaArray<AyaMapData, u32>,
    retirement_owner: u64,
    retirement_failed: bool,
    #[cfg(test)]
    retirement_faults: retirement::RetirementFaults,
    tcp_proof_link: Option<aya::programs::sock_ops::SockOpsLink>,
    /// Runtime probe for `BPF_MAP_LOOKUP_BATCH` (janitor map scans).
    cap_lookup_batch: BatchCapability,
    cap_flow_lookup_batch: BatchCapability,
    tcp_live_pins: std::sync::Arc<AyaMapData>,
    /// Active compiled program, links, descriptor, and generation-owned maps.
    routing_generation: Option<routing::RoutingGeneration>,
    routing_slot: u32,
    routing_generation_counter: u64,
    routing_generation_sequence: AyaArray<AyaMapData, u64>,
    next_trace_policy: u32,
    #[cfg(feature = "native-api")]
    trace_dictionaries: crate::observe::flows::kernel::KernelTraceDictionaries,
    #[cfg(feature = "native-api")]
    receive_trace: Option<std::sync::Arc<receive_trace::ReceiveTrace>>,
    #[cfg(feature = "native-api")]
    receive_trace_available: bool,
    #[cfg(feature = "native-api")]
    receive_trace_attempted: bool,
    udp_staging_quiesce_incomplete: bool,
    aux_deletes: AuxDeleteTally,
}

/// Find cgroup2 in the calling thread's mount namespace, not its thread-group leader's.
fn detect_cgroup_path() -> anyhow::Result<String> {
    let mounts = std::fs::read_to_string("/proc/thread-self/mounts")?;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[2] == "cgroup2" {
            return Ok(fields[1].to_string());
        }
    }
    anyhow::bail!("cgroup2 not mounted")
}

impl RealEbpfBackend {
    fn publish_listener_socket_maps(
        &mut self,
        tcp4_fd: RawFd,
        tcp6_fd: Option<RawFd>,
        udp4_fds: &[RawFd],
        udp6_fds: &[RawFd],
    ) -> anyhow::Result<()> {
        self.listeners_published = false;
        let entries = std::iter::once((0u32, tcp4_fd)).chain(tcp6_fd.map(|fd| (1u32, fd)));
        let entries = entries.chain(
            udp4_fds
                .iter()
                .enumerate()
                .map(|(index, fd)| (2 + index as u32, *fd)),
        );
        let entries = entries.chain(
            udp6_fds
                .iter()
                .enumerate()
                .map(|(index, fd)| (6 + index as u32, *fd)),
        );
        {
            let map = self
                .bpf_mut()?
                .map_mut("LISTEN_SOCKET_MAP")
                .ok_or_else(|| anyhow::anyhow!("map 'LISTEN_SOCKET_MAP' not found"))?;
            let mut sockets = AyaSockMap::try_from(map)
                .map_err(|error| anyhow::anyhow!("map 'LISTEN_SOCKET_MAP': {error}"))?;
            for (key, fd) in entries {
                // The control plane owns every listener for this entire call.
                let socket = unsafe { BorrowedFd::borrow_raw(fd) };
                sockets.set(key, &socket, 0).map_err(|error| {
                    anyhow::anyhow!("map 'LISTEN_SOCKET_MAP' set[{key}]: {error}")
                })?;
                debug!(fd, key, "Published listener socket to LISTEN_SOCKET_MAP");
            }
        }
        self.listeners_published = true;
        Ok(())
    }

    #[inline(always)]
    fn bpf(&self) -> anyhow::Result<&Ebpf> {
        self.bpf
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("eBPF object not loaded"))
    }

    #[inline(always)]
    fn bpf_mut(&mut self) -> anyhow::Result<&mut Ebpf> {
        self.bpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("eBPF object not loaded"))
    }
}

mod attach;
mod bindings;
mod btf;
mod events;
mod iface_watch;
mod interface_startup;
mod interface_state;
mod layout;
mod observation;
mod process_name;
#[cfg(feature = "native-api")]
pub(crate) mod receive_trace;
mod retirement;
mod routing;
pub(crate) mod syscall;
mod tcp_binding;
#[cfg(test)]
mod tests;

pub use events::*;
pub use iface_watch::IfaceWatcher;
pub(crate) use interface_startup::start_interfaces;
use syscall::{
    bpf_lookup_batch_scan_cb, reset_udp_decision_sequence_locked,
    validate_loaded_udp_decision_sequence,
};
pub use tcp_binding::TcpKernelPin;

fn conn_key(outbound: u8, domain: u32, ipver: u32) -> u32 {
    (outbound as u32)
        .wrapping_mul(6)
        .wrapping_add(domain.wrapping_mul(2))
        .wrapping_add(ipver)
}

fn set_array_value<V: Pod>(
    bpf: &mut Ebpf,
    name: &str,
    index: u32,
    value: &V,
) -> anyhow::Result<()> {
    let map = bpf
        .map_mut(name)
        .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))?;
    let mut array = AyaArray::<_, V>::try_from(map)
        .map_err(|error| anyhow::anyhow!("map '{name}': {error}"))?;
    array
        .set(index, value, 0)
        .map_err(|error| anyhow::anyhow!("map '{name}' set[{index}]: {error}"))
}

/// Chunked visitor used by the batch map scanners.
type ChunkVisitor<'a, K, V> = dyn FnMut(&[(K, V)]) -> bool + 'a;

impl RealEbpfBackend {
    fn hash_map<'a, K: Pod, V: Pod>(
        &'a self,
        name: &str,
    ) -> anyhow::Result<AyaHashMap<&'a AyaMapData, K, V>> {
        let map = self
            .bpf()?
            .map(name)
            .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))?;
        AyaHashMap::try_from(map).map_err(|error| anyhow::anyhow!("map '{name}': {error}"))
    }

    fn hash_map_mut<'a, K: Pod, V: Pod>(
        &'a mut self,
        name: &str,
    ) -> anyhow::Result<AyaHashMap<&'a mut AyaMapData, K, V>> {
        let map = self
            .bpf_mut()?
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))?;
        AyaHashMap::try_from(map).map_err(|error| anyhow::anyhow!("map '{name}': {error}"))
    }

    #[cfg(test)]
    fn hash_insert<K: Pod, V: Pod>(
        &mut self,
        name: &str,
        key: &K,
        value: &V,
    ) -> anyhow::Result<()> {
        self.hash_map_mut::<K, V>(name)?
            .insert(key, value, 0)
            .map_err(|error| anyhow::anyhow!("map '{name}' insert: {error}"))
    }

    fn hash_insert_noexist<K: Pod, V: Pod>(
        &mut self,
        name: &str,
        key: &K,
        value: &V,
    ) -> anyhow::Result<()> {
        const BPF_NOEXIST: u64 = 1;
        self.hash_map_mut::<K, V>(name)?
            .insert(key, value, BPF_NOEXIST)
            .map_err(|error| anyhow::anyhow!("map '{name}' no-exist insert: {error}"))
    }

    fn hash_lookup<K: Pod, V: Pod>(&self, name: &str, key: &K) -> anyhow::Result<Option<V>> {
        match self.hash_map(name)?.get(key, 0) {
            Ok(value) => Ok(Some(value)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(anyhow::anyhow!("map '{name}' lookup: {error}")),
        }
    }

    pub(crate) fn flow_lookup<K: Pod, V: Pod>(
        &self,
        name: &str,
        key: &K,
    ) -> anyhow::Result<Option<V>> {
        match self
            .hash_map::<K, FlowMapValue<V>>(name)?
            .get(key, aya_obj::generated::BPF_F_LOCK as u64)
        {
            Ok(value) => Ok(Some(value.value)),
            Err(error) if Self::map_error_is_missing(&error) => Ok(None),
            Err(error) => Err(anyhow::anyhow!("map '{name}' locked lookup: {error}")),
        }
    }

    pub(crate) fn flow_insert<K: Pod, V: Pod>(
        &mut self,
        name: &str,
        key: &K,
        value: &V,
    ) -> anyhow::Result<()> {
        self.hash_map_mut::<K, FlowMapValue<V>>(name)?
            .insert(
                key,
                &FlowMapValue::new(*value),
                aya_obj::generated::BPF_F_LOCK as u64,
            )
            .map_err(|error| anyhow::anyhow!("map '{name}' locked insert: {error}"))
    }

    pub(crate) fn flow_for_each_chunk<K: Pod, V: Pod>(
        &self,
        name: &str,
        chunk_size: usize,
        visit: &mut ChunkVisitor<'_, K, V>,
    ) -> anyhow::Result<()> {
        self.flow_scan_from(
            name,
            chunk_size,
            &mut crate::ebpf::FlowScanCursor::default(),
            visit,
        )
    }

    fn flow_scan_from<K: Pod, V: Pod>(
        &self,
        name: &str,
        chunk_size: usize,
        cursor: &mut crate::ebpf::FlowScanCursor,
        visit: &mut ChunkVisitor<'_, K, V>,
    ) -> anyhow::Result<()> {
        let mut projected = Vec::with_capacity(syscall::BPF_BATCH_CHUNK);
        if syscall::bpf_lookup_batch_scan_cb_flags::<K, FlowMapValue<V>>(
            self.bpf()?,
            &self.cap_flow_lookup_batch,
            name,
            aya_obj::generated::BPF_F_LOCK as u64,
            &mut cursor.batch,
            &mut |chunk| {
                projected.clear();
                projected.extend(chunk.iter().map(|(key, value)| (*key, value.value)));
                visit(&projected)
            },
        )? {
            return Ok(());
        }
        // backend R excludes userspace reclamation; kernel never deletes tuple
        // elements. Enumerate keys only, then copy each payload under its lock.
        anyhow::ensure!(
            core::mem::size_of::<K>() == 40,
            "tuple scan key must be 40 bytes"
        );
        let fd = syscall::map_fd(self.bpf()?, name)?;
        let mut next = match cursor.next_key.take() {
            Some(key) => Some(key),
            None => syscall::next_flow_key(fd, None)?,
        };
        projected.clear();
        while let Some(raw) = next {
            let key = unsafe { core::ptr::read_unaligned(raw.as_ptr().cast::<K>()) };
            // Save an unvisited key, not one this sweep may retire after backend R.
            next = syscall::next_flow_key(fd, Some(&raw))?;
            if let Some(value) = self.flow_lookup(name, &key)? {
                projected.push((key, value));
                if projected.len() == chunk_size.max(1) {
                    if !visit(&projected) {
                        cursor.next_key = next;
                        return Ok(());
                    }
                    projected.clear();
                }
            }
        }
        if !projected.is_empty() {
            visit(&projected);
        }
        Ok(())
    }

    /// Sum each slot of a per-CPU `u64` array over all CPUs; a map the object
    /// lacks reads as zero.
    fn percpu_totals<const N: usize>(
        &self,
        name: &str,
        slots: [u32; N],
    ) -> anyhow::Result<[u64; N]> {
        let mut totals = [0u64; N];
        let Some(map) = self.bpf()?.map(name) else {
            return Ok(totals);
        };
        let array = AyaPerCpuArray::<_, u64>::try_from(map)
            .map_err(|error| anyhow::anyhow!("map '{name}': {error}"))?;
        for (total, slot) in totals.iter_mut().zip(slots) {
            match array.get(&slot, 0) {
                Ok(values) => {
                    *total = values
                        .iter()
                        .fold(0u64, |sum, value| sum.wrapping_add(*value));
                }
                Err(MapError::KeyNotFound) => {}
                Err(error) => {
                    return Err(anyhow::anyhow!("map '{name}' get[{slot}]: {error}"));
                }
            }
        }
        Ok(totals)
    }

    fn hash_remove<K: Pod, V: Pod>(&mut self, name: &str, key: &K) -> anyhow::Result<()> {
        match self.hash_map_mut::<K, V>(name)?.remove(key) {
            Ok(()) => Ok(()),
            Err(error) if Self::map_error_is_missing(&error) => Ok(()),
            Err(error) => Err(anyhow::anyhow!("map '{name}' delete: {error}")),
        }
    }

    fn hash_remove_present<K: Pod, V: Pod>(&mut self, name: &str, key: &K) -> anyhow::Result<bool> {
        #[cfg(test)]
        if name != RETIRE_FENCE_MAP {
            retirement::inject_indexed_fault(&mut self.retirement_faults.delete, "delete")?;
        }
        match self.hash_map_mut::<K, V>(name)?.remove(key) {
            Ok(()) => Ok(true),
            Err(error) if Self::map_error_is_missing(&error) => Ok(false),
            Err(error) => Err(anyhow::anyhow!("map '{name}' delete: {error}")),
        }
    }

    fn map_error_is_missing(error: &MapError) -> bool {
        matches!(error, MapError::KeyNotFound)
            || matches!(
                error,
                MapError::SyscallError(error)
                    if error.io_error.raw_os_error() == Some(libc::ENOENT)
            )
    }

    fn sockmap_slot_is_empty(error: &MapError) -> bool {
        // Linux __sock_map_delete returns EINVAL for vacant slots; Aya checks
        // index bounds before issuing this SOCKMAP-specific syscall.
        Self::map_error_is_missing(error)
            || matches!(error,
            MapError::SyscallError(error) if error.io_error.raw_os_error() == Some(libc::EINVAL))
    }

    fn array_set<V: Pod>(&mut self, name: &str, index: u32, value: &V) -> anyhow::Result<()> {
        set_array_value(self.bpf_mut()?, name, index, value)
    }

    fn array_get<V: Pod>(&self, name: &str, index: u32) -> anyhow::Result<Option<V>> {
        let map = self
            .bpf()?
            .map(name)
            .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))?;
        let array = AyaArray::<_, V>::try_from(map)
            .map_err(|error| anyhow::anyhow!("map '{name}': {error}"))?;
        match array.get(&index, 0) {
            Ok(value) => Ok(Some(value)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(anyhow::anyhow!("map '{name}' get[{index}]: {error}")),
        }
    }

    fn for_each_map_chunk<K: Pod, V: Pod>(
        &self,
        name: &str,
        chunk_size: usize,
        visit: &mut ChunkVisitor<'_, K, V>,
    ) -> anyhow::Result<()> {
        let bpf = self.bpf()?;
        if bpf_lookup_batch_scan_cb(bpf, &self.cap_lookup_batch, name, visit)? {
            return Ok(());
        }
        let mut chunk = Vec::with_capacity(chunk_size.max(1));
        for entry in self.hash_map(name)?.iter() {
            chunk.push(entry.map_err(|error| anyhow::anyhow!("map '{name}' iteration: {error}"))?);
            if chunk.len() == chunk_size.max(1) {
                if !visit(&chunk) {
                    return Ok(());
                }
                chunk.clear();
            }
        }
        if !chunk.is_empty() {
            visit(&chunk);
        }
        Ok(())
    }

    /// The pin root defaults to `/sys/fs/bpf`, which every other BPF consumer on the host also
    /// pins into, so cleanup unlinks the names this instance claimed rather than sweeping the
    /// directory. Neither persistent sequence is claimed, so both survive ordinary cleanup,
    /// including cleanup by an older object that does not know the routing sequence pin.
    fn remove_nonpersistent_pins(&self) -> std::io::Result<()> {
        for name in &self.pinned_maps {
            if let Err(error) = std::fs::remove_file(self.pin_root.join(name))
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(error);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl EbpfBackend for RealEbpfBackend {
    fn observe_datapath(&self) -> super::DatapathObservation {
        self.observe_backend()
    }

    fn interface_binding_snapshot(&self) -> anyhow::Result<super::interface::BindingSnapshot> {
        self.bindings.snapshot()
    }

    fn commit_interface_bindings(
        &mut self,
        commit: super::interface::BindingCommit,
    ) -> Vec<std::os::fd::OwnedFd> {
        self.bindings.commit(commit)
    }

    fn set_datapath_ready(&mut self, ready: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            !ready || !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        if ready && !self.listeners_published {
            anyhow::bail!("listener socket generation is not fully published");
        }
        self.array_set("DATAPATH_STATE_MAP", 0, &u32::from(ready))
    }

    fn set_datapath_flags(&mut self, flags: u32) -> anyhow::Result<()> {
        anyhow::ensure!(
            flags & DATAPATH_FLAG_NFQ_READY == 0
                || (!self.udp_staging_quiesce_incomplete && !self.retirement_failed),
            "UDP staging quiescence must complete before NFQUEUE can reopen"
        );
        self.array_set("DATAPATH_FLAGS_MAP", 0, &flags)
    }

    fn quiesce_udp_staging(&mut self) -> anyhow::Result<()> {
        self.quiesce_staged_udp()
    }

    fn publish_routing_plan(
        &mut self,
        plan: &crate::control::routing_matcher::RoutingPushPlan,
        learned_domains: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()> {
        self.publish_compiled_routing(plan, learned_domains)
    }

    fn routing_policy_generation(&self) -> u64 {
        self.routing_generation_counter
    }

    fn active_routing_slot(&self) -> anyhow::Result<u32> {
        Ok(self.routing_slot)
    }

    fn add_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let map = self.active_domain_mut().map_err(anyhow::Error::from)?;
        let mut value = match map.get(&ip_key.data, 0) {
            Ok(value) => value,
            Err(error) if Self::map_error_is_missing(&error) => DomainRouting::default(),
            Err(error) => return Err(anyhow::anyhow!("active domain map lookup: {error}")),
        };
        for (current, update) in value.bitmap.iter_mut().zip(bitmap.bitmap) {
            *current |= update;
        }
        map.insert(&ip_key.data, &value, 0)
            .map_err(|error| anyhow::anyhow!("active domain map insert: {error}"))
    }

    fn set_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> Result<(), super::DomainRouteWriteError> {
        match self.active_domain_mut()?.insert(&ip_key.data, bitmap, 0) {
            Ok(()) => Ok(()),
            Err(MapError::SyscallError(error))
                if matches!(
                    error.io_error.raw_os_error(),
                    Some(libc::ENOSPC) | Some(libc::E2BIG)
                ) =>
            {
                Err(super::DomainRouteWriteError::MapFull)
            }
            Err(error) => Err(super::DomainRouteWriteError::Other(anyhow::anyhow!(
                "active domain map insert: {error}"
            ))),
        }
    }

    fn remove_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
    ) -> Result<(), super::DomainRouteWriteError> {
        match self.active_domain_mut()?.remove(&ip_key.data) {
            Ok(()) => Ok(()),
            Err(error) if Self::map_error_is_missing(&error) => Ok(()),
            Err(error) => Err(super::DomainRouteWriteError::Other(anyhow::anyhow!(
                "active domain map delete: {error}"
            ))),
        }
    }

    fn conn_state_lookup(&self, key: &TuplesKey) -> anyhow::Result<Option<ConnState>> {
        self.flow_lookup("CONN_STATE_MAP", key)
    }
    #[cfg(test)]
    fn tcp_conn_state_store(&mut self, k: &TuplesKey, s: &ConnState) -> anyhow::Result<()> {
        self.flow_insert("CONN_STATE_MAP", k, s)
    }
    #[cfg(test)]
    fn udp_conn_state_store(&mut self, k: &TuplesKey, s: &ConnState) -> anyhow::Result<()> {
        self.flow_insert("CONN_STATE_MAP", k, s)
    }

    fn udp_flow_owner(
        &self,
        token: u32,
        state: Option<ConnState>,
    ) -> anyhow::Result<super::UdpFlowOwner> {
        anyhow::ensure!(
            !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        let state =
            state.ok_or_else(|| anyhow::anyhow!("UDP admission has no current conn state"))?;
        anyhow::ensure!(state.decision_token == token, "UDP admission token changed");
        super::UdpFlowOwner::new(token, Some(state.incarnation))
    }

    fn commit_udp_decision(
        &mut self,
        key: &TuplesKey,
        token: u32,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        if matches!(transition, UdpDecisionTransition::ActivateDirect(_)) {
            self.activate_udp_direct(key, token, transition)
        } else {
            self.commit_udp_fenced(key, token, transition)
        }
    }

    fn commit_udp_batch(
        &mut self,
        requests: &[crate::ebpf::UdpDecisionCommit],
        visit: &mut crate::ebpf::UdpCommitVisit<'_>,
    ) -> anyhow::Result<()> {
        self.commit_udp_decisions(requests, visit)
    }

    fn retire_batch(
        &mut self,
        requests: &[RetireRequest<'_>],
        outcomes: &mut [RetireOutcome],
    ) -> Result<RetireCounts, RetireError> {
        self.retire_flows(requests, outcomes)
    }

    fn adopt_tcp(
        &self,
        fd: BorrowedFd<'_>,
        tuples: &TuplesKey,
        errors: super::TcpPinErrorSink,
    ) -> anyhow::Result<super::TcpAdoption> {
        tcp_binding::adopt(self, fd, tuples, errors)
    }

    #[cfg(test)]
    fn tcp_socket_ownership(&self, fd: BorrowedFd<'_>) -> anyhow::Result<TcpSocketOwnership> {
        anyhow::ensure!(
            !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        Ok(TcpSocketOwnership::Kernel(tcp_binding::lookup(
            self.bpf()?,
            fd,
        )?))
    }

    fn take_expiry_hints(&mut self) -> Option<tokio::sync::mpsc::Receiver<FlowExpiryHint>> {
        self.expiry_hints.take()
    }

    fn verify_udp_decision_sequence(&self) -> anyhow::Result<()> {
        validate_loaded_udp_decision_sequence(self.bpf()?).map(|_| ())
    }
    fn udp_decision_sequence_status(&self) -> anyhow::Result<UdpDecisionSequenceStatus> {
        let sequence = validate_loaded_udp_decision_sequence(self.bpf()?)?;
        Ok(UdpDecisionSequenceStatus {
            next: sequence.next & UDP_DECISION_SEQUENCE_MASK,
            generation: udp_decision_token_generation(sequence.next),
        })
    }

    fn reset_udp_decision_sequence(&mut self, generation: u32) -> anyhow::Result<bool> {
        anyhow::ensure!(
            generation <= UDP_DECISION_GENERATION_MASK,
            "invalid UDP decision generation {generation}"
        );
        anyhow::ensure!(
            self.udp_decision_sequence_status()?.exhausted(),
            "UDP decision sequence is not exhausted"
        );
        let conflicts_with_rollback =
            |token| token != 0 && udp_decision_token_generation(token) >= generation;
        let mut live = false;
        self.flow_for_each_chunk::<TuplesKey, ConnState>("CONN_STATE_MAP", 256, &mut |chunk| {
            live = chunk
                .iter()
                .any(|(_, state)| conflicts_with_rollback(state.decision_token));
            !live
        })?;
        if !live {
            self.for_each_map_chunk::<TuplesKey, honk_ebpf_common::conn::RetirementFence>(
                RETIRE_FENCE_MAP,
                256,
                &mut |chunk| {
                    live = chunk
                        .iter()
                        .any(|(_, fence)| conflicts_with_rollback(fence.decision_token));
                    !live
                },
            )?;
        }

        if !live {
            self.flow_for_each_chunk::<TuplesKey, RoutingHandoffEntry>(
                "ROUTING_HANDOFF_MAP",
                256,
                &mut |chunk| {
                    live = chunk
                        .iter()
                        .any(|(_, entry)| conflicts_with_rollback(entry.result.decision_token));
                    !live
                },
            )?;
        }
        if !live {
            self.flow_for_each_chunk::<RedirectTuple, RedirectEntry>(
                "REDIRECT_TRACK",
                256,
                &mut |chunk| {
                    live = chunk
                        .iter()
                        .any(|(_, entry)| conflicts_with_rollback(entry.decision_token));
                    !live
                },
            )?;
        }
        if live {
            return Ok(false);
        }
        reset_udp_decision_sequence_locked(self.bpf()?, generation)?;
        Ok(true)
    }

    fn routing_handoff_lookup(
        &self,
        key: &TuplesKey,
    ) -> anyhow::Result<Option<RoutingHandoffEntry>> {
        self.flow_lookup("ROUTING_HANDOFF_MAP", key)
    }

    fn redirect_track_lookup(&self, k: &RedirectTuple) -> anyhow::Result<Option<RedirectEntry>> {
        self.flow_lookup("REDIRECT_TRACK", k)
    }
    #[cfg(test)]
    fn redirect_track_store(&mut self, k: &RedirectTuple, e: &RedirectEntry) -> anyhow::Result<()> {
        self.flow_insert("REDIRECT_TRACK", k, e)
    }

    #[cfg(feature = "native-api")]
    fn bind_kernel_trace_dictionary(
        &mut self,
        dictionary: crate::observe::flows::kernel::KernelTraceDictionary,
    ) {
        if let Some(owner) = &self.routing_generation {
            self.trace_dictionaries
                .bind(owner.trace_policy, owner.fingerprint, dictionary);
        }
    }

    #[cfg(feature = "native-api")]
    fn capture_kernel_route(
        &self,
        key: &TuplesKey,
        reference: crate::observe::flows::kernel::KernelRouteReference,
    ) -> Result<crate::observe::flows::kernel::CapturedKernelRoute, &'static str> {
        if reference.trace_id == 0 {
            return Err("kernel_trace_not_captured");
        }
        if reference.trace_id == ROUTE_TRACE_LOST {
            return Err("kernel_trace_lost");
        }
        let witness = self
            .hash_lookup::<_, KernelRouteWitness>("ROUTE_TRACE_MAP", &reference.trace_id)
            .map_err(|_| "kernel_trace_lookup_failed")?
            .ok_or("kernel_trace_sidecar_missing")?;
        self.trace_dictionaries.capture(&witness, key, reference)
    }

    /// Without the cgroup hooks `pname()` never matches and `!pname()`
    /// always does; without argv capture they see the thread name.
    fn pname_support(&self) -> super::PnameSupport {
        if self.cgroup_sock_links.is_empty() {
            super::PnameSupport::Unavailable
        } else if self.pname_mode == process_name::PnameCaptureMode::Comm {
            super::PnameSupport::ThreadName
        } else {
            super::PnameSupport::Full
        }
    }

    #[cfg(feature = "native-api")]
    fn receive_trace(&mut self) -> Option<std::sync::Arc<receive_trace::ReceiveTrace>> {
        if !self.receive_trace_attempted {
            // Kernel/loader offsets are fixed for this backend, and a partially loaded Aya
            // program cannot be loaded again on listener reload. Restart retries attachment.
            self.receive_trace_attempted = true;
            if !self.receive_trace_available {
                warn!(
                    ipv4_unavailable = true,
                    ipv6_unavailable = true,
                    "kernel UDP trace unavailable: checked BTF offsets missing"
                );
            } else {
                let result = btf::load_kernel().and_then(|(_, kernel_btf)| {
                    receive_trace::ReceiveTrace::attach(self.bpf_mut()?, &kernel_btf)
                });
                match result {
                    Ok(trace) => self.receive_trace = Some(trace),
                    Err(error) => warn!(
                        error = %format_args!("{error:#}"),
                        ipv4_unavailable = true,
                        ipv6_unavailable = true,
                        "kernel UDP trace attach unavailable"
                    ),
                }
            }
        }
        self.receive_trace.clone()
    }

    fn redirect_track_for_each_chunk(
        &self,
        chunk_size: usize,
        cursor: &mut crate::ebpf::FlowScanCursor,
        visit: &mut crate::ebpf::RedirectTrackChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.flow_scan_from("REDIRECT_TRACK", chunk_size, cursor, visit)
    }

    fn routing_handoff_for_each_chunk(
        &self,
        chunk_size: usize,
        cursor: &mut crate::ebpf::FlowScanCursor,
        visit: &mut crate::ebpf::RoutingHandoffChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.flow_scan_from("ROUTING_HANDOFF_MAP", chunk_size, cursor, visit)
    }

    fn conn_state_for_each_chunk(
        &self,
        chunk_size: usize,
        cursor: &mut crate::ebpf::FlowScanCursor,
        visit: &mut crate::ebpf::ConnStateChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.flow_scan_from("CONN_STATE_MAP", chunk_size, cursor, visit)
    }

    fn conn_state_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        let [inserts, deletes] = self.percpu_totals(
            "CONN_STATE_OCCUPANCY",
            [
                honk_ebpf_common::conn::OCCUPANCY_INSERTS,
                honk_ebpf_common::conn::OCCUPANCY_EBPF_DELETES,
            ],
        )?;
        Ok((inserts, deletes))
    }

    fn aux_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        let [redirect, handoff] = self.percpu_totals(
            "AUX_OCCUPANCY",
            [
                honk_ebpf_common::conn::AUX_OCCUPANCY_REDIRECT_INSERTS,
                honk_ebpf_common::conn::AUX_OCCUPANCY_HANDOFF_INSERTS,
            ],
        )?;
        Ok((
            redirect.saturating_sub(self.aux_deletes.redirect),
            handoff.saturating_sub(self.aux_deletes.handoff),
        ))
    }

    fn set_admission_pressure(&mut self, pressured: bool) -> anyhow::Result<()> {
        self.array_set("ADMISSION_PRESSURE", 0, &u32::from(pressured))
    }

    fn set_outbound_alive(
        &mut self,
        outbound: u8,
        domain: u32,
        ipver: u32,
        alive: bool,
    ) -> anyhow::Result<()> {
        let key = conn_key(outbound, domain, ipver);
        self.array_set("OUTBOUND_CONNECTIVITY_MAP", key, &u64::from(alive))
    }

    fn get_outbound_alive(&self, outbound: u8, domain: u32, ipver: u32) -> anyhow::Result<bool> {
        let key = conn_key(outbound, domain, ipver);
        Ok(self
            .array_get::<u64>("OUTBOUND_CONNECTIVITY_MAP", key)?
            .unwrap_or(0)
            != 0)
    }

    fn get_bpf_stats(&self, k: u32) -> anyhow::Result<Option<u64>> {
        self.array_get("BPF_STATS_MAP", k)
    }

    fn detach_hooks(&mut self) -> anyhow::Result<()> {
        // Drop all TC links, which detaches the eBPF programs from the
        // network interfaces and restores normal packet processing.
        info!("Detaching BPF hooks (interface bindings, cgroup, dae0, sk_lookup)");
        self.bindings.release();
        self.tcp_proof_link = None;
        self.cgroup_sock_links.clear();
        self.cgroup_sock_addr_links.clear();
        self.dae0_ingress_link = None;
        self.dae0peer_ingress_link = None;
        self.sk_lookup_link = None;
        info!("BPF hooks detached, network restored");
        Ok(())
    }

    fn attach_dae0_programs(&mut self) -> anyhow::Result<()> {
        // Both LAN and WAN-only deployments need this link to deliver proxied replies.
        let id = Self::attach_tc(self.bpf_mut()?, "dae0_ingress", "dae0")
            .map_err(|error| anyhow::anyhow!("attach dae0_ingress: {error}"))?;
        let program: &mut aya::programs::SchedClassifier = self
            .bpf_mut()?
            .program_mut("dae0_ingress")
            .ok_or_else(|| anyhow::anyhow!("dae0_ingress program disappeared"))?
            .try_into()?;
        self.dae0_ingress_link = Some(
            program
                .take_link(id)
                .map_err(|error| anyhow::anyhow!("take dae0_ingress link: {error}"))?,
        );
        info!("dae0_ingress attached and link held");

        Ok(())
    }

    fn attach_dae0peer_ingress(&mut self) -> anyhow::Result<()> {
        // dae0peer lives in the daens namespace; enter it with a scoped
        // `with_daens_netns` switch for the attach (the process otherwise
        // stays in the host netns). Interface names for the TCX link resolve
        // in the attaching thread's netns; the link handle persists after
        // switching back to the host netns.
        crate::daens::with_daens_netns("attach dae0peer_ingress", move || {
            let id = Self::attach_tc(self.bpf_mut()?, "dae0peer_ingress", "dae0peer")
                .map_err(|error| anyhow::anyhow!("attach dae0peer_ingress: {error}"))?;
            let program: &mut aya::programs::SchedClassifier = self
                .bpf_mut()?
                .program_mut("dae0peer_ingress")
                .ok_or_else(|| anyhow::anyhow!("dae0peer_ingress program disappeared"))?
                .try_into()?;
            self.dae0peer_ingress_link = Some(
                program
                    .take_link(id)
                    .map_err(|error| anyhow::anyhow!("take dae0peer_ingress link: {error}"))?,
            );
            info!("dae0peer_ingress attached and link held");
            Ok(())
        })
    }

    fn attach_sk_lookup(&mut self) -> anyhow::Result<()> {
        // The sk_lookup program attaches to the daens namespace; run the
        // whole attach inside a scoped `with_daens_netns` switch (the process
        // otherwise stays in the host netns).  The TPROXY listener sockets
        // live in daens too (bound there via a scoped switch at control-plane
        // startup), so proxy-bound packets are assigned to them in their own
        // namespace.  The link handle persists after switching back.
        crate::daens::with_daens_netns("attach tproxy_sk_lookup", move || {
            let netns = crate::daens::daens_fd()?;
            let p: &mut aya::programs::SkLookup = self
                .bpf_mut()?
                .program_mut("tproxy_sk_lookup")
                .ok_or_else(|| anyhow::anyhow!("tproxy_sk_lookup program not found"))?
                .try_into()?;
            p.load()
                .map_err(|e| anyhow::anyhow!("load tproxy_sk_lookup: {}", e))?;
            let id = p
                .attach(netns)
                .map_err(|e| anyhow::anyhow!("attach tproxy_sk_lookup: {}", e))?;
            self.sk_lookup_link = Some(
                p.take_link(id)
                    .map_err(|e| anyhow::anyhow!("take tproxy_sk_lookup link: {}", e))?,
            );
            info!("tproxy_sk_lookup attached to daens namespace");
            Ok(())
        })
    }

    fn publish_listener_sockets(
        &mut self,
        tcp4_fd: RawFd,
        tcp6_fd: Option<RawFd>,
        udp4_fds: &[RawFd],
        udp6_fds: &[RawFd],
    ) -> anyhow::Result<()> {
        self.listeners_published = false;
        anyhow::ensure!(
            self.tcp_proof_link.is_some(),
            "required TCP ownership hooks are not attached"
        );
        self.publish_listener_socket_maps(tcp4_fd, tcp6_fd, udp4_fds, udp6_fds)
    }

    fn clear_listener_sockets(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.array_get::<u32>("DATAPATH_STATE_MAP", 0)? == Some(0),
            "datapath admission must be closed before clearing listeners"
        );
        // Invalidation precedes removal: a partial failure must not permit READY.
        self.listeners_published = false;
        let map = self
            .bpf_mut()?
            .map_mut("LISTEN_SOCKET_MAP")
            .ok_or_else(|| anyhow::anyhow!("listener socket map unavailable"))?;
        let mut sockets = AyaSockMap::try_from(map)?;
        for key in 0..10 {
            match sockets.clear_index(&key) {
                Ok(()) => {}
                Err(error) if Self::sockmap_slot_is_empty(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    async fn cleanup(&mut self) -> anyhow::Result<()> {
        // Detach eBPF programs immediately to restore network connectivity.
        self.detach_hooks()?;

        // Stop the aya-log flush task before dropping the Ebpf object.
        if let Some(h) = self.log_flush_handle.take() {
            h.abort();
            let _ = h.await;
        }
        // The root and generated freplace links remain valid until every
        // network entry point is detached above.
        self.routing_generation = None;
        // Stop the DaeEvent ringbuf consumer as well; it owns the
        // EVENT_RINGBUF MapData taken out of the Ebpf object.
        if let Some(h) = self.event_flush_handle.take() {
            h.abort();
            let _ = h.await;
        }
        #[cfg(feature = "native-api")]
        drop(self.receive_trace.take());

        // Drop object map fds before unlinking generation-owned pins; both
        // persistent sequence pins survive ordinary shutdown.
        if let Some(bpf) = self.bpf.take() {
            drop(bpf);
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if let Err(error) = self.remove_nonpersistent_pins() {
            if error.raw_os_error() == Some(libc::EBUSY) {
                debug!(
                    "BPF pin still busy after teardown, will be cleaned up later: {}",
                    error
                );
            } else {
                warn!("cleanup transient BPF pins: {}", error);
            }
        }
        Ok(())
    }
}

impl Drop for RealEbpfBackend {
    fn drop(&mut self) {
        let _ = self.detach_hooks();
        // Normal cleanup joins these nonblocking consumers. Drop must still
        // cancel them instead of detaching a ring/map/channel owner forever.
        if let Some(handle) = self.event_flush_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.log_flush_handle.take() {
            handle.abort();
        }
        self.routing_generation = None;
        let _ = self.remove_nonpersistent_pins();
    }
}
