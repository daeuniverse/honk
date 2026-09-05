use async_trait::async_trait;
use aya::maps::lpm_trie::Key as AyaLpmKey;
use aya::maps::{
    Array as AyaArray, HashMap as AyaHashMap, LpmTrie as AyaLpmTrie, MapData as AyaMapData,
    MapError, PerCpuArray as AyaPerCpuArray, PerCpuValues, SockMap as AyaSockMap,
};
use aya::{Ebpf, EbpfLoader, Pod};

use honk_ebpf_common::*;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use super::{
    EbpfBackend, LpmKeepSet, UDP_DECISION_EPOCH_MAP, UDP_DECISION_INFLIGHT_MAP,
    UDP_DECISION_RETIRE_FENCE_MAP, UDP_DECISION_SEQUENCE_MAP, USERSPACE_CONN_STATE_DELETES,
    UdpDecisionCommitResult, UdpDecisionSequenceStatus, UdpDecisionTransition,
    apply_udp_decision_transition, maps, probe::BatchCapability,
    udp_state_is_legacy_userspace_owned, udp_state_is_userspace_owned,
    validate_udp_decision_transition,
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
/// Normal map operations go through Aya's typed APIs. The small raw syscall
/// extension is restricted to atomic lookup-and-delete and batch commands
/// that Aya 0.14 does not expose.
pub struct RealEbpfBackend {
    bpf: Option<Ebpf>,
    pin_root: PathBuf,
    /// Map names this instance claimed at attach, so cleanup unlinks what it owns instead of
    /// everything under a pin root that is shared with every other BPF consumer.
    pinned_maps: Vec<String>,
    tproxy_port: u16,
    tproxy_mark: u32,
    /// Every TC link attached to a configured interface, including the four
    /// primary LAN/WAN hooks, startup bridge/bond slaves, extra configured
    /// interfaces, and watcher rebinds. Keying ownership by (ifindex,is_egress)
    /// lets a reconnect release stale primary links and makes a
    /// retry observe hooks that are still live instead of stacking them.
    interface_links: Vec<(u32, bool, aya::programs::tc::SchedClassifierLink)>,
    /// cgroup sock_create/sock_release links (cookie→PID mapping, control-plane
    /// bypass). Held for the backend lifetime — dropping one detaches the
    /// program in the kernel.
    cgroup_sock_links: Vec<aya::programs::cgroup_sock::CgroupSockLink>,
    /// cgroup connect4/6 + sendmsg4/6 links; same lifetime rule as above.
    cgroup_sock_addr_links: Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>,
    dae0_ingress_link: Option<aya::programs::tc::SchedClassifierLink>,
    dae0peer_ingress_link: Option<aya::programs::tc::SchedClassifierLink>,
    sk_lookup_link: Option<aya::programs::sk_lookup::SkLookupLink>,
    listeners_published: bool,
    /// Background task that flushes aya-log ring-buffer records.
    log_flush_handle: Option<tokio::task::JoinHandle<()>>,
    /// Background task that drains EVENT_RINGBUF (DaeEvent) into the log.
    event_flush_handle: Option<tokio::task::JoinHandle<()>>,
    /// Runtime probe for `BPF_MAP_LOOKUP_AND_DELETE_ELEM` (handoff take).
    cap_lookup_and_delete: BatchCapability,
    /// Runtime probe for `BPF_MAP_LOOKUP_BATCH` (janitor map scans).
    cap_lookup_batch: BatchCapability,
    /// Runtime probe for `BPF_MAP_DELETE_BATCH` (janitor batch deletes).
    cap_delete_batch: BatchCapability,
    /// Runtime probe for `BPF_MAP_UPDATE_BATCH` (routing rule pushes).
    cap_update_batch: BatchCapability,
}

/// Detect the first cgroup2 mount point from /proc/mounts.
/// Returns the mount path (e.g. /sys/fs/cgroup) if found.
fn detect_cgroup_path() -> anyhow::Result<String> {
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[2] == "cgroup2" {
            return Ok(fields[1].to_string());
        }
    }
    anyhow::bail!("cgroup2 not mounted")
}

impl RealEbpfBackend {
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
mod events;
mod iface_watch;
mod process_name;
mod syscall;

pub use events::*;
pub use iface_watch::{AttachedInterface, AttachedMap, IfaceWatcher};
use syscall::{
    LookupAndDelete, bpf_delete_batch, bpf_delete_shared, bpf_lookup_and_delete,
    bpf_lookup_batch_scan, bpf_lookup_batch_scan_cb, bpf_update_batch,
    reset_udp_decision_sequence_locked, validate_loaded_udp_decision_sequence,
};

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

    fn hash_remove<K: Pod, V: Pod>(&mut self, name: &str, key: &K) -> anyhow::Result<()> {
        match self.hash_map_mut::<K, V>(name)?.remove(key) {
            Ok(()) => Ok(()),
            Err(error) if Self::map_error_is_missing(&error) => Ok(()),
            Err(error) => Err(anyhow::anyhow!("map '{name}' delete: {error}")),
        }
    }

    fn hash_remove_present<K: Pod, V: Pod>(&mut self, name: &str, key: &K) -> anyhow::Result<bool> {
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

    fn lpm_insert(
        &mut self,
        name: &str,
        key: &LpmKey,
        value: &DomainRouting,
    ) -> anyhow::Result<()> {
        let map = self
            .bpf_mut()?
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))?;
        let mut trie = AyaLpmTrie::<_, [u32; 4], DomainRouting>::try_from(map)
            .map_err(|error| anyhow::anyhow!("map '{name}': {error}"))?;
        trie.insert(&AyaLpmKey::new(key.prefix_len, key.data), value, 0)
            .map_err(|error| anyhow::anyhow!("map '{name}' insert: {error}"))
    }

    fn lpm_keys(&self, name: &str) -> anyhow::Result<Vec<AyaLpmKey<[u32; 4]>>> {
        let map = self
            .bpf()?
            .map(name)
            .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))?;
        let trie = AyaLpmTrie::<_, [u32; 4], DomainRouting>::try_from(map)
            .map_err(|error| anyhow::anyhow!("map '{name}': {error}"))?;
        trie.keys()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| anyhow::anyhow!("map '{name}' keys: {error}"))
    }

    fn lpm_remove(&mut self, name: &str, key: &AyaLpmKey<[u32; 4]>) -> anyhow::Result<()> {
        let map = self
            .bpf_mut()?
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))?;
        let mut trie = AyaLpmTrie::<_, [u32; 4], DomainRouting>::try_from(map)
            .map_err(|error| anyhow::anyhow!("map '{name}': {error}"))?;
        match trie.remove(key) {
            Ok(()) => Ok(()),
            Err(error) if Self::map_error_is_missing(&error) => Ok(()),
            Err(error) => Err(anyhow::anyhow!("map '{name}' delete: {error}")),
        }
    }

    fn domain_insert(
        &mut self,
        key: &[u32; 4],
        value: &DomainRouting,
    ) -> Result<(), super::DomainRouteWriteError> {
        let mut map = self
            .hash_map_mut::<[u32; 4], DomainRouting>("DOMAIN_ROUTING_MAP")
            .map_err(super::DomainRouteWriteError::Other)?;
        match map.insert(key, value, 0) {
            Ok(()) => Ok(()),
            Err(MapError::SyscallError(error))
                if error.io_error.raw_os_error() == Some(libc::ENOSPC) =>
            {
                Err(super::DomainRouteWriteError::MapFull)
            }
            Err(error) => Err(super::DomainRouteWriteError::Other(anyhow::anyhow!(
                "map 'DOMAIN_ROUTING_MAP' insert: {error}"
            ))),
        }
    }

    /// Snapshot all entries of a hash-family map. Batch commands remain an
    /// optimization; Aya iteration is the compatibility fallback.
    fn map_snapshot<K: Pod, V: Pod>(
        &self,
        name: &str,
        out: &mut Vec<(K, V)>,
    ) -> anyhow::Result<()> {
        let bpf = self.bpf()?;
        if bpf_lookup_batch_scan(bpf, &self.cap_lookup_batch, name, out)? {
            return Ok(());
        }
        for entry in self.hash_map(name)?.iter() {
            out.push(entry.map_err(|error| anyhow::anyhow!("map '{name}' iteration: {error}"))?);
        }
        Ok(())
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

    fn map_delete_batch<K: Pod, V: Pod>(&mut self, name: &str, keys: &[K]) -> anyhow::Result<()> {
        if bpf_delete_batch(self.bpf()?, &self.cap_delete_batch, name, keys)? {
            return Ok(());
        }
        let mut map = self.hash_map_mut::<K, V>(name)?;
        for key in keys {
            if let Err(error) = map.remove(key)
                && !Self::map_error_is_missing(&error)
            {
                return Err(anyhow::anyhow!("map '{name}' delete: {error}"));
            }
        }
        Ok(())
    }

    fn or_update_domain_bitmap(
        &mut self,
        key: &[u32; 4],
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let mut current = *bitmap;
        if let Some(existing) = self.hash_lookup::<_, DomainRouting>("DOMAIN_ROUTING_MAP", key)? {
            for (current, existing) in current.bitmap.iter_mut().zip(existing.bitmap) {
                *current |= existing;
            }
        }
        self.hash_insert("DOMAIN_ROUTING_MAP", key, &current)
    }

    fn rotate_udp_decision_epoch(&mut self) -> anyhow::Result<u32> {
        let previous = self
            .array_get::<u32>(UDP_DECISION_EPOCH_MAP, 0)?
            .unwrap_or(0)
            & 1;
        self.array_set(UDP_DECISION_EPOCH_MAP, 0, &(previous ^ 1))?;
        Ok(previous)
    }

    fn wait_udp_decision_slot(&self, slot: u32) -> anyhow::Result<()> {
        let bpf = self.bpf()?;
        let map = bpf
            .map(UDP_DECISION_INFLIGHT_MAP)
            .ok_or_else(|| anyhow::anyhow!("map '{UDP_DECISION_INFLIGHT_MAP}' not found"))?;
        let array = AyaPerCpuArray::<_, u32>::try_from(map)
            .map_err(|error| anyhow::anyhow!("map '{UDP_DECISION_INFLIGHT_MAP}': {error}"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let active = match array.get(&(slot & 1), 0) {
                Ok(values) => values
                    .iter()
                    .fold(0u64, |total, value| total.wrapping_add(*value as u64)),
                Err(MapError::KeyNotFound) => 0,
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "map '{UDP_DECISION_INFLIGHT_MAP}' get[{slot}]: {error}"
                    ));
                }
            };
            if active == 0 {
                return Ok(());
            }
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "UDP decision grace period {slot} did not quiesce"
            );
            std::thread::yield_now();
        }
    }

    fn with_udp_retirement_fence(
        &mut self,
        key: &TuplesKey,
        token: u32,
        operation: impl FnOnce(&mut Self) -> anyhow::Result<UdpDecisionCommitResult>,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        self.hash_insert_noexist(UDP_DECISION_RETIRE_FENCE_MAP, key, &token)?;
        let result = (|| {
            let previous = self.rotate_udp_decision_epoch()?;
            self.wait_udp_decision_slot(previous)?;
            operation(self)
        })();
        let release = match self.hash_lookup::<_, u32>(UDP_DECISION_RETIRE_FENCE_MAP, key)? {
            Some(current) if current == token => {
                self.hash_remove::<_, u32>(UDP_DECISION_RETIRE_FENCE_MAP, key)
            }
            Some(current) => Err(anyhow::anyhow!(
                "UDP retirement fence token changed from {token} to {current}"
            )),
            None => Err(anyhow::anyhow!(
                "UDP retirement fence for token {token} disappeared"
            )),
        };
        release?;
        result
    }

    fn remove_token_bound_udp_flow(
        &mut self,
        key: &TuplesKey,
        token: u32,
        pending_only: bool,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        if token == 0 && !pending_only {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        self.with_udp_retirement_fence(key, token, |backend| {
            let Some(state) = backend.hash_lookup::<_, ConnState>("CONN_STATE_MAP", key)? else {
                return Ok(UdpDecisionCommitResult::Missing);
            };
            if state.decision_token != token {
                return Ok(if pending_only {
                    UdpDecisionCommitResult::TokenMismatch
                } else {
                    UdpDecisionCommitResult::Superseded
                });
            }
            let state_allowed = if pending_only {
                state.state == UdpDecisionState::Preparing as u8
                    || state.state == UdpDecisionState::Pending as u8
            } else {
                udp_state_is_userspace_owned(state.state)
            };
            if !state_allowed {
                return Ok(UdpDecisionCommitResult::StateMismatch);
            }
            let handoff =
                backend.hash_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
            if handoff.is_some_and(|entry| entry.result.decision_token != token) {
                return Ok(UdpDecisionCommitResult::TokenMismatch);
            }
            let track_key = RedirectTuple::from_tuples(key);
            let track = backend.hash_lookup::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?;
            if track.is_some_and(|entry| entry.decision_token != token) {
                return Ok(UdpDecisionCommitResult::TokenMismatch);
            }
            if handoff.is_some() {
                backend.hash_remove::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
            }
            if track.is_some() {
                backend.hash_remove::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?;
            }
            if !backend.hash_remove_present::<_, ConnState>("CONN_STATE_MAP", key)? {
                return Ok(UdpDecisionCommitResult::Missing);
            }
            USERSPACE_CONN_STATE_DELETES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(UdpDecisionCommitResult::Applied)
        })
    }

    /// The pin root defaults to `/sys/fs/bpf`, which every other BPF consumer on the host also
    /// pins into, so cleanup unlinks the names this instance claimed rather than sweeping the
    /// directory. `UDP_DECISION_SEQUENCE` is never in that list — attach pins it through
    /// `map_pin_path` and skips the loop — so the persistent allocator survives by construction.
    /// A name the current object no longer contains is no longer swept; the sweep used to remove
    /// it, and nothing else does now.
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
    fn attach_dynamic_interface(
        &mut self,
        ifname: &str,
        role: super::IfaceRole,
        single_homed: bool,
    ) -> anyhow::Result<super::DynamicHooks> {
        match role {
            super::IfaceRole::Lan => self.attach_lan(ifname, single_homed),
            super::IfaceRole::Wan => {
                self.attach_wan_egress(ifname)?;
                self.attach_wan_ingress(ifname)?;
                Ok(super::DynamicHooks {
                    ingress: true,
                    egress: true,
                })
            }
            super::IfaceRole::LanWan => {
                self.attach_lan(ifname, true)?;
                self.attach_wan_egress(ifname)?;
                Ok(super::DynamicHooks {
                    ingress: true,
                    egress: true,
                })
            }
            super::IfaceRole::WanBondSlave => {
                self.attach_wan_egress(ifname)?;
                Ok(super::DynamicHooks {
                    ingress: false,
                    egress: true,
                })
            }
            super::IfaceRole::LanBridgeSlave | super::IfaceRole::LanBondSlave => {
                self.attach_slave(ifname, role)
            }
        }
    }

    fn forget_dynamic_interface(&mut self, ifindex: u32) {
        // The device may still exist when an auto-resolved route changes, so
        // dropping every owned link for this ifindex must perform the detach
        // before a later reconcile attempts to bind it again.
        self.interface_links.retain(|(i, _, _)| *i != ifindex);
    }

    fn set_datapath_ready(&mut self, ready: bool) -> anyhow::Result<()> {
        if ready && !self.listeners_published {
            anyhow::bail!("listener socket generation is not fully published");
        }
        self.array_set("DATAPATH_STATE_MAP", 0, &u32::from(ready))
    }

    fn set_datapath_flags(&mut self, flags: u32) -> anyhow::Result<()> {
        self.array_set("DATAPATH_FLAGS_MAP", 0, &flags)
    }

    fn quiesce_udp_staging(&mut self) -> anyhow::Result<()> {
        let previous = self.rotate_udp_decision_epoch()?;
        self.wait_udp_decision_slot(previous)?;

        let mut staged = Vec::new();
        self.for_each_map_chunk::<TuplesKey, ConnState>("CONN_STATE_MAP", 256, &mut |chunk| {
            staged.extend(chunk.iter().filter_map(|(key, state)| {
                (state.state == UdpDecisionState::Preparing as u8
                    || state.state == UdpDecisionState::Pending as u8)
                    .then_some((*key, state.decision_token))
            }));
            true
        })?;
        for (key, token) in staged {
            let result = self.remove_token_bound_udp_flow(&key, token, true)?;
            anyhow::ensure!(
                matches!(
                    result,
                    UdpDecisionCommitResult::Applied | UdpDecisionCommitResult::Missing
                ),
                "UDP staging quiescence rejected token {token}: {result:?}"
            );
        }
        Ok(())
    }

    fn set_param(&mut self, _key: ParamKey, _value: u32) -> anyhow::Result<()> {
        // The Rust eBPF code uses Global<DaeParam> instead of PARAM_MAP.
        // All parameters are set via inject() which writes to the global.
        // Individual set_param calls are no-ops for compatibility.
        Ok(())
    }
    fn get_param(&self, _key: ParamKey) -> anyhow::Result<Option<u32>> {
        Ok(None)
    }

    fn set_routing_rules(&mut self, generation: u32, rules: &[MatchSet]) -> anyhow::Result<()> {
        let base = generation * MAX_MATCH_SET_LEN;
        let keys: Vec<u32> = (base..base + rules.len() as u32).collect();
        if bpf_update_batch(
            self.bpf()?,
            &self.cap_update_batch,
            "ROUTING_MAP",
            &keys,
            rules,
        )? {
            return Ok(());
        }
        for (i, rule) in rules.iter().enumerate() {
            self.array_set("ROUTING_MAP", base + i as u32, rule)?;
        }
        Ok(())
    }

    fn active_routing_generation(&self) -> anyhow::Result<u32> {
        Ok(self
            .array_get::<u32>("ROUTING_META_MAP", ROUTING_META_ACTIVE_GENERATION_SLOT)?
            .unwrap_or(0))
    }
    fn publish_routing_generation(
        &mut self,
        generation: u32,
        count: u32,
        group_bitmaps: &RoutingGroupBitmaps,
    ) -> anyhow::Result<()> {
        for (group, words) in group_bitmaps.iter().enumerate() {
            for (word, value) in words.iter().enumerate() {
                let slot = routing_meta_bitmap_base(generation)
                    + (group * ROUTING_GROUP_BITMAP_WORDS + word) as u32;
                self.array_set("ROUTING_META_MAP", slot, value)?;
            }
        }
        self.array_set(
            "ROUTING_META_MAP",
            routing_meta_count_slot(generation),
            &count,
        )?;
        for (group, bitmap) in group_bitmaps.iter().enumerate() {
            let meta = RoutingGroupMeta {
                rule_count: count,
                bitmap: *bitmap,
            };
            self.array_set(
                "ROUTING_GROUP_META_MAP",
                routing_group_meta_index(generation, group as u32),
                &meta,
            )?;
        }
        self.array_set(
            "ROUTING_META_MAP",
            ROUTING_META_ACTIVE_GENERATION_SLOT,
            &generation,
        )
    }

    fn add_domain_route(&mut self, domain: &str, outbound: OutboundIndex) -> anyhow::Result<()> {
        let hash = maps::fnv1a_hash(domain.as_bytes());
        let key = [hash as u32, (hash >> 32) as u32, 0, 0];
        let mut current = self
            .hash_lookup::<_, DomainRouting>("DOMAIN_ROUTING_MAP", &key)?
            .unwrap_or_default();
        let outbound = outbound as u32;
        let word = (outbound / 32) as usize;
        if word < ROUTING_BITMAP_WORDS_PER_GENERATION {
            let generation = self.active_routing_generation()? as usize;
            current.bitmap[generation * ROUTING_BITMAP_WORDS_PER_GENERATION + word] |=
                1 << (outbound % 32);
        }
        self.hash_insert("DOMAIN_ROUTING_MAP", &key, &current)
    }

    fn add_domain_routing_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let bitmap = bitmap.for_generation(self.active_routing_generation()?);
        self.or_update_domain_bitmap(&key.data, &bitmap)
    }

    fn add_dest_lpm_bitmap(&mut self, key: &LpmKey, bitmap: &DomainRouting) -> anyhow::Result<()> {
        self.lpm_insert("DEST_LPM_ROUTING_MAP", key, bitmap)
    }

    fn add_source_lpm_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        self.lpm_insert("SOURCE_LPM_ROUTING_MAP", key, bitmap)
    }

    fn add_mac_lpm_bitmap(&mut self, key: &LpmKey, bitmap: &DomainRouting) -> anyhow::Result<()> {
        self.lpm_insert("MAC_LPM_ROUTING_MAP", key, bitmap)
    }

    fn add_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let bitmap = bitmap.for_generation(self.active_routing_generation()?);
        self.or_update_domain_bitmap(&ip_key.data, &bitmap)
    }

    fn set_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> Result<(), super::DomainRouteWriteError> {
        let generation = self
            .active_routing_generation()
            .map_err(super::DomainRouteWriteError::Other)?;
        let mut current = self
            .hash_lookup::<_, DomainRouting>("DOMAIN_ROUTING_MAP", &ip_key.data)
            .map_err(super::DomainRouteWriteError::Other)?
            .unwrap_or_default();
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        current.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION]
            .copy_from_slice(&bitmap.bitmap[..ROUTING_BITMAP_WORDS_PER_GENERATION]);
        self.domain_insert(&ip_key.data, &current)
    }

    fn remove_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
    ) -> Result<(), super::DomainRouteWriteError> {
        let generation = self
            .active_routing_generation()
            .map_err(super::DomainRouteWriteError::Other)?;
        let Some(mut bitmap) = self
            .hash_lookup::<_, DomainRouting>("DOMAIN_ROUTING_MAP", &ip_key.data)
            .map_err(super::DomainRouteWriteError::Other)?
        else {
            return Ok(());
        };
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        bitmap.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION].fill(0);
        if bitmap.bitmap.iter().all(|word| *word == 0) {
            self.hash_remove::<_, DomainRouting>("DOMAIN_ROUTING_MAP", &ip_key.data)
                .map_err(super::DomainRouteWriteError::Other)
        } else {
            self.domain_insert(&ip_key.data, &bitmap)
        }
    }

    fn stage_domain_routing_generation(
        &mut self,
        generation: u32,
        entries: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            generation < ROUTING_BITMAP_GENERATIONS as u32,
            "invalid routing generation {generation}"
        );
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        let keys = self
            .hash_map::<[u32; 4], DomainRouting>("DOMAIN_ROUTING_MAP")?
            .keys()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| anyhow::anyhow!("map 'DOMAIN_ROUTING_MAP' keys: {error}"))?;
        for key in keys {
            let Some(mut bitmap) =
                self.hash_lookup::<_, DomainRouting>("DOMAIN_ROUTING_MAP", &key)?
            else {
                continue;
            };
            bitmap.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION].fill(0);
            self.hash_insert("DOMAIN_ROUTING_MAP", &key, &bitmap)?;
        }
        for (key, logical) in entries {
            let mut bitmap = self
                .hash_lookup::<_, DomainRouting>("DOMAIN_ROUTING_MAP", &key.data)?
                .unwrap_or_default();
            bitmap.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION]
                .copy_from_slice(&logical.bitmap[..ROUTING_BITMAP_WORDS_PER_GENERATION]);
            self.hash_insert("DOMAIN_ROUTING_MAP", &key.data, &bitmap)?;
        }
        Ok(())
    }

    fn add_ip_route(&mut self, prefix: &str, outbound: OutboundIndex) -> anyhow::Result<()> {
        let key = maps::cidr_to_lpm_key(prefix)?;
        let mut routing = DomainRouting::default();
        let outbound = outbound as u32;
        let word = (outbound / 32) as usize;
        if word < ROUTING_BITMAP_WORDS_PER_GENERATION {
            routing.bitmap[word] = 1 << (outbound % 32);
        }
        let routing = routing.for_generation(self.active_routing_generation()?);
        self.hash_insert("DOMAIN_ROUTING_MAP", &key.data, &routing)
    }

    fn clear_routes(&mut self) -> anyhow::Result<()> {
        let empty_rule = MatchSet::default();
        for index in 0..ROUTING_MAP_LEN as u32 {
            self.array_set("ROUTING_MAP", index, &empty_rule)?;
        }
        for index in 0..ROUTING_META_MAP_LEN as u32 {
            self.array_set("ROUTING_META_MAP", index, &0u32)?;
        }
        for index in 0..ROUTING_GROUP_META_MAP_LEN as u32 {
            self.array_set(
                "ROUTING_GROUP_META_MAP",
                index,
                &RoutingGroupMeta::default(),
            )?;
        }
        let domain_keys = self
            .hash_map::<[u32; 4], DomainRouting>("DOMAIN_ROUTING_MAP")?
            .keys()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| anyhow::anyhow!("map 'DOMAIN_ROUTING_MAP' keys: {error}"))?;
        for key in domain_keys {
            self.hash_remove::<_, DomainRouting>("DOMAIN_ROUTING_MAP", &key)?;
        }
        for name in [
            "DEST_LPM_ROUTING_MAP",
            "SOURCE_LPM_ROUTING_MAP",
            "MAC_LPM_ROUTING_MAP",
        ] {
            for key in self.lpm_keys(name)? {
                self.lpm_remove(name, &key)?;
            }
        }
        Ok(())
    }

    fn prune_lpm_entries(&mut self, keep: &LpmKeepSet) -> anyhow::Result<()> {
        // Retain both banks for one transition so readers that captured the
        // previous selector cannot lose an LPM value mid-evaluation.
        for (name, retained) in [
            ("DEST_LPM_ROUTING_MAP", &keep.dest),
            ("SOURCE_LPM_ROUTING_MAP", &keep.source),
            ("MAC_LPM_ROUTING_MAP", &keep.mac),
        ] {
            for key in self.lpm_keys(name)? {
                let key_bytes = maps::lpm_key_bytes(&LpmKey {
                    prefix_len: key.prefix_len(),
                    data: key.data(),
                });
                if !retained.contains(&key_bytes) {
                    self.lpm_remove(name, &key)?;
                }
            }
        }
        Ok(())
    }

    fn tcp_conn_state_lookup(&self, k: &TuplesKey) -> anyhow::Result<Option<ConnState>> {
        self.hash_lookup("CONN_STATE_MAP", k)
    }
    fn tcp_conn_state_store(&mut self, k: &TuplesKey, s: &ConnState) -> anyhow::Result<()> {
        self.hash_insert("CONN_STATE_MAP", k, s)
    }
    fn tcp_conn_state_remove(&mut self, k: &TuplesKey) -> anyhow::Result<()> {
        self.hash_remove::<_, ConnState>("CONN_STATE_MAP", k)
    }

    fn udp_conn_state_lookup(&self, k: &TuplesKey) -> anyhow::Result<Option<ConnState>> {
        self.hash_lookup("CONN_STATE_MAP", k)
    }
    fn udp_conn_state_store(&mut self, k: &TuplesKey, s: &ConnState) -> anyhow::Result<()> {
        self.hash_insert("CONN_STATE_MAP", k, s)
    }
    fn udp_conn_state_remove(&mut self, k: &TuplesKey) -> anyhow::Result<()> {
        self.hash_remove::<_, ConnState>("CONN_STATE_MAP", k)
    }

    fn commit_udp_decision(
        &mut self,
        key: &TuplesKey,
        token: u32,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        validate_udp_decision_transition(transition)?;
        if token == 0 {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let Some(mut state) = self.hash_lookup::<_, ConnState>("CONN_STATE_MAP", key)? else {
            return Ok(UdpDecisionCommitResult::Missing);
        };
        if state.decision_token != token {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        if let Err(result) = apply_udp_decision_transition(&mut state, transition) {
            return Ok(result);
        }
        let handoff = self.hash_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
        if handoff.is_some_and(|entry| entry.result.decision_token != token) {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let track_key = RedirectTuple::from_tuples(key);
        let track = self.hash_lookup::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?;
        if track.is_some_and(|entry| entry.decision_token != token) {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let initial_transition = !matches!(transition, UdpDecisionTransition::ActivateDirect(_));
        if initial_transition && (handoff.is_none() || track.is_none()) {
            return Ok(UdpDecisionCommitResult::Missing);
        }

        if handoff.is_some() {
            self.hash_remove::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
        }
        match transition {
            UdpDecisionTransition::ActivateProxy(outbound, _) => {
                let mut track = track.expect("proxy track checked above");
                track.outbound = outbound;
                self.hash_insert("REDIRECT_TRACK", &track_key, &track)?;
            }
            UdpDecisionTransition::ArmDirect(_)
            | UdpDecisionTransition::ActivateDirect(_)
            | UdpDecisionTransition::Block => {
                if track.is_some() {
                    self.hash_remove::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?;
                }
            }
        }
        self.hash_insert("CONN_STATE_MAP", key, &state)?;
        Ok(UdpDecisionCommitResult::Applied)
    }

    fn abort_pending_udp_flow(
        &mut self,
        key: &TuplesKey,
        token: u32,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        self.remove_token_bound_udp_flow(key, token, true)
    }

    fn remove_udp_flow(
        &mut self,
        key: &TuplesKey,
        token: u32,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        if token != 0 {
            return self.remove_token_bound_udp_flow(key, token, false);
        }
        self.with_udp_retirement_fence(key, 0, |backend| {
            let Some(state) = backend.hash_lookup::<_, ConnState>("CONN_STATE_MAP", key)? else {
                return Ok(UdpDecisionCommitResult::Missing);
            };
            if !udp_state_is_legacy_userspace_owned(&state) {
                return Ok(UdpDecisionCommitResult::Superseded);
            }
            if !backend.hash_remove_present::<_, ConnState>("CONN_STATE_MAP", key)? {
                return Ok(UdpDecisionCommitResult::Missing);
            }
            USERSPACE_CONN_STATE_DELETES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(UdpDecisionCommitResult::Applied)
        })
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
        self.for_each_map_chunk::<TuplesKey, ConnState>("CONN_STATE_MAP", 256, &mut |chunk| {
            live = chunk
                .iter()
                .any(|(_, state)| conflicts_with_rollback(state.decision_token));
            !live
        })?;
        if !live {
            self.for_each_map_chunk::<TuplesKey, u32>(
                UDP_DECISION_RETIRE_FENCE_MAP,
                256,
                &mut |chunk| {
                    live = chunk
                        .iter()
                        .any(|(_, token)| conflicts_with_rollback(*token));
                    !live
                },
            )?;
        }

        if !live {
            self.for_each_map_chunk::<TuplesKey, RoutingHandoffEntry>(
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
            self.for_each_map_chunk::<RedirectTuple, RedirectEntry>(
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
        self.hash_lookup("ROUTING_HANDOFF_MAP", key)
    }

    fn redirect_track_lookup(&self, k: &RedirectTuple) -> anyhow::Result<Option<RedirectEntry>> {
        self.hash_lookup("REDIRECT_TRACK", k)
    }
    fn redirect_track_store(&mut self, k: &RedirectTuple, e: &RedirectEntry) -> anyhow::Result<()> {
        self.hash_insert("REDIRECT_TRACK", k, e)
    }
    fn redirect_track_remove(&mut self, k: &RedirectTuple) -> anyhow::Result<()> {
        self.hash_remove::<_, RedirectEntry>("REDIRECT_TRACK", k)
    }

    fn routing_handoff_take(&self, key: &TuplesKey) -> anyhow::Result<Option<RoutingHandoffEntry>> {
        let bpf = self.bpf()?;
        match bpf_lookup_and_delete::<_, RoutingHandoffEntry>(
            bpf,
            &self.cap_lookup_and_delete,
            "ROUTING_HANDOFF_MAP",
            key,
        )? {
            LookupAndDelete::Value(entry) => return Ok(Some(entry)),
            LookupAndDelete::Missing => return Ok(None),
            LookupAndDelete::Unsupported => {}
        }
        // The pre-4.20 fallback is intentionally non-atomic. A concurrent
        // replacement can be dropped, but this handoff is only a routing hint.
        let entry = self.hash_lookup("ROUTING_HANDOFF_MAP", key)?;
        if entry.is_some() {
            bpf_delete_shared(bpf, "ROUTING_HANDOFF_MAP", key)?;
        }
        Ok(entry)
    }

    fn cookie_pid_lookup(&self, c: u64) -> anyhow::Result<Option<PIDName>> {
        self.hash_lookup("COOKIE_PID_MAP", &c)
    }
    fn cookie_pid_store(&mut self, c: u64, e: &PIDName) -> anyhow::Result<()> {
        self.hash_insert("COOKIE_PID_MAP", &c, e)
    }
    fn cookie_pid_remove(&mut self, cookie: &u64) -> anyhow::Result<()> {
        self.hash_remove::<_, PIDName>("COOKIE_PID_MAP", cookie)
    }

    fn redirect_track_snapshot(
        &self,
        out: &mut Vec<(RedirectTuple, RedirectEntry)>,
    ) -> anyhow::Result<()> {
        self.map_snapshot("REDIRECT_TRACK", out)
    }

    fn redirect_track_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut crate::ebpf::RedirectTrackChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.for_each_map_chunk("REDIRECT_TRACK", chunk_size, visit)
    }

    fn cookie_pid_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut crate::ebpf::CookiePidChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.for_each_map_chunk("COOKIE_PID_MAP", chunk_size, visit)
    }

    fn routing_handoff_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut crate::ebpf::RoutingHandoffChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.for_each_map_chunk("ROUTING_HANDOFF_MAP", chunk_size, visit)
    }

    fn conn_state_snapshot(&self, out: &mut Vec<(TuplesKey, ConnState)>) -> anyhow::Result<()> {
        self.map_snapshot("CONN_STATE_MAP", out)
    }

    fn conn_state_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut crate::ebpf::ConnStateChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.for_each_map_chunk("CONN_STATE_MAP", chunk_size, visit)
    }

    fn conn_state_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<()> {
        self.map_delete_batch::<_, ConnState>("CONN_STATE_MAP", keys)
    }

    fn conn_state_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        let bpf = self.bpf()?;
        let Some(map) = bpf.map("CONN_STATE_OCCUPANCY") else {
            return Ok((0, 0));
        };
        let array = AyaPerCpuArray::<_, u64>::try_from(map)
            .map_err(|error| anyhow::anyhow!("map 'CONN_STATE_OCCUPANCY': {error}"))?;
        let mut totals = [0u64; 2];
        for (index, slot) in [
            honk_ebpf_common::conn::OCCUPANCY_INSERTS,
            honk_ebpf_common::conn::OCCUPANCY_EBPF_DELETES,
        ]
        .into_iter()
        .enumerate()
        {
            match array.get(&slot, 0) {
                Ok(values) => {
                    totals[index] = values
                        .iter()
                        .fold(0u64, |total, value| total.wrapping_add(*value));
                }
                Err(MapError::KeyNotFound) => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "map 'CONN_STATE_OCCUPANCY' get[{slot}]: {error}"
                    ));
                }
            }
        }
        Ok((totals[0], totals[1]))
    }

    fn cookie_pid_snapshot(&self, out: &mut Vec<(u64, PIDName)>) -> anyhow::Result<()> {
        self.map_snapshot("COOKIE_PID_MAP", out)
    }

    fn routing_handoff_snapshot(
        &self,
        out: &mut Vec<(TuplesKey, RoutingHandoffEntry)>,
    ) -> anyhow::Result<()> {
        self.map_snapshot("ROUTING_HANDOFF_MAP", out)
    }

    fn redirect_track_remove_batch(&mut self, keys: &[RedirectTuple]) -> anyhow::Result<()> {
        self.map_delete_batch::<_, RedirectEntry>("REDIRECT_TRACK", keys)
    }

    fn cookie_pid_remove_batch(&mut self, cookies: &[u64]) -> anyhow::Result<()> {
        self.map_delete_batch::<_, PIDName>("COOKIE_PID_MAP", cookies)
    }

    fn routing_handoff_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<()> {
        self.map_delete_batch::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", keys)
    }

    fn conn_state_remove_if_unchanged(
        &mut self,
        entries: &[(TuplesKey, ConnState)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (key, scanned) in entries {
            if self
                .hash_lookup::<_, ConnState>("CONN_STATE_MAP", key)?
                .is_some_and(|current| {
                    current.last_seen_ns == scanned.last_seen_ns
                        && current.state == scanned.state
                        && current.last_seen_ns <= expired_before_ns
                })
            {
                self.hash_remove::<_, ConnState>("CONN_STATE_MAP", key)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn redirect_track_remove_if_unchanged(
        &mut self,
        entries: &[(RedirectTuple, RedirectEntry)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (key, scanned) in entries {
            if self
                .hash_lookup::<_, RedirectEntry>("REDIRECT_TRACK", key)?
                .is_some_and(|current| {
                    current.last_seen_ns == scanned.last_seen_ns
                        && current.last_seen_ns <= expired_before_ns
                })
            {
                self.hash_remove::<_, RedirectEntry>("REDIRECT_TRACK", key)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn cookie_pid_remove_if_unchanged(
        &mut self,
        entries: &[(u64, PIDName)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (cookie, scanned) in entries {
            if self
                .hash_lookup::<_, PIDName>("COOKIE_PID_MAP", cookie)?
                .is_some_and(|current| {
                    current.last_seen_ns == scanned.last_seen_ns
                        && current.last_seen_ns <= expired_before_ns
                })
            {
                self.hash_remove::<_, PIDName>("COOKIE_PID_MAP", cookie)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn routing_handoff_remove_if_unchanged(
        &mut self,
        entries: &[(TuplesKey, RoutingHandoffEntry)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (key, scanned) in entries {
            if self
                .hash_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?
                .is_some_and(|current| {
                    current.last_seen_ns == scanned.last_seen_ns
                        && current.last_seen_ns <= expired_before_ns
                })
            {
                self.hash_remove::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
                removed += 1;
            }
        }
        Ok(removed)
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

    fn get_outbound_stats(&self, outbound: OutboundIndex) -> anyhow::Result<OutboundStats> {
        let bpf = self.bpf()?;
        let Some(map) = bpf.map("OUTBOUND_STATS") else {
            return Ok(OutboundStats::default());
        };
        let array = AyaPerCpuArray::<_, OutboundStatsCounters>::try_from(map)
            .map_err(|error| anyhow::anyhow!("map 'OUTBOUND_STATS': {error}"))?;
        let index = OutboundStatsCounters::for_outbound(outbound as u8);
        let values = match array.get(&index, 0) {
            Ok(values) => values,
            Err(MapError::KeyNotFound) => return Ok(OutboundStats::default()),
            Err(error) => {
                anyhow::bail!("map 'OUTBOUND_STATS' get[{index}]: {error}");
            }
        };
        let mut stats = OutboundStats::default();
        for counters in values.iter() {
            stats.tx_packets = stats.tx_packets.wrapping_add(counters.tx_packets);
            stats.tx_bytes = stats.tx_bytes.wrapping_add(counters.tx_bytes);
            stats.rx_packets = stats.rx_packets.wrapping_add(counters.rx_packets);
            stats.rx_bytes = stats.rx_bytes.wrapping_add(counters.rx_bytes);
        }
        Ok(stats)
    }
    fn clear_outbound_stats(&mut self, outbound: OutboundIndex) -> anyhow::Result<()> {
        if self.bpf()?.map("OUTBOUND_STATS").is_none() {
            return Ok(());
        }
        let cpu_count = aya::util::nr_cpus()
            .map_err(|(path, error)| anyhow::anyhow!("read {path}: {error}"))?;
        let zeros = PerCpuValues::try_from(vec![OutboundStatsCounters::default(); cpu_count])?;
        let map = self
            .bpf_mut()?
            .map_mut("OUTBOUND_STATS")
            .ok_or_else(|| anyhow::anyhow!("map 'OUTBOUND_STATS' not found"))?;
        let mut array = AyaPerCpuArray::<_, OutboundStatsCounters>::try_from(map)
            .map_err(|error| anyhow::anyhow!("map 'OUTBOUND_STATS': {error}"))?;
        let index = OutboundStatsCounters::for_outbound(outbound as u8);
        array
            .set(index, zeros, 0)
            .map_err(|error| anyhow::anyhow!("map 'OUTBOUND_STATS' set[{index}]: {error}"))
    }
    fn get_bpf_stats(&self, k: u32) -> anyhow::Result<Option<u64>> {
        self.array_get("BPF_STATS_MAP", k)
    }

    fn conn_track_lookup(&self, _: &ConnTuple) -> anyhow::Result<Option<u32>> {
        Ok(None)
    }
    fn conn_track_store(&mut self, _: &ConnTuple, _: u32) -> anyhow::Result<()> {
        Ok(())
    }
    fn conn_track_remove(&mut self, _: &ConnTuple) -> anyhow::Result<()> {
        Ok(())
    }

    fn detach_hooks(&mut self) -> anyhow::Result<()> {
        // Drop all TC links, which detaches the eBPF programs from the
        // network interfaces and restores normal packet processing.
        info!(
            "Detaching BPF hooks (lan_ingress, lan_egress, wan_egress, wan_ingress, bond slaves, bridge slaves, cgroup, dae0, sk_lookup)"
        );
        self.interface_links.clear();
        self.cgroup_sock_links.clear();
        self.cgroup_sock_addr_links.clear();
        self.dae0_ingress_link = None;
        self.dae0peer_ingress_link = None;
        self.sk_lookup_link = None;
        info!("BPF hooks detached, network restored");
        Ok(())
    }

    fn eject(&mut self) {
        if let Err(error) = self.remove_nonpersistent_pins() {
            warn!("cleanup transient BPF pins: {}", error);
        }
    }

    fn inject(&mut self, p: &super::BpfLoadParams) -> anyhow::Result<()> {
        // The Rust eBPF code uses Global<DaeParam> (.rodata).
        // Globals must be set via EbpfLoader::override_global() before load().
        // For now, store local fields; the global defaults (all zeros) suffice
        // for basic operation. Full parameter injection requires restructuring
        // the load flow to set globals via the loader.
        self.tproxy_port = p.tproxy_port;
        self.tproxy_mark = p.tproxy_mark;
        info!(
            "PARAM defaults in effect (tproxy_port={}, tproxy_mark=0x{:x})",
            p.tproxy_port, p.tproxy_mark
        );
        Ok(())
    }

    fn attach_dae0_programs(&mut self) -> anyhow::Result<()> {
        // Ensure clsact qdisc exists on dae0 and dae0peer before attaching the
        // TC programs; otherwise netlink returns EINVAL.
        for iface in &["dae0", "dae0peer"] {
            if let Err(e) = aya::programs::tc::qdisc_add_clsact(iface)
                && !e.to_string().contains("File exists")
            {
                warn!("failed to add clsact qdisc to {}: {}", iface, e);
            }
        }

        // dae0_ingress runs on dae0 (host namespace) and rewrites reply traffic
        // back to the original LAN interface.
        match Self::attach_tc(self.bpf_mut()?, "dae0_ingress", "dae0") {
            Ok(id) => {
                let p: &mut aya::programs::SchedClassifier = self
                    .bpf_mut()?
                    .program_mut("dae0_ingress")
                    .ok_or_else(|| anyhow::anyhow!("dae0_ingress program disappeared"))?
                    .try_into()?;
                self.dae0_ingress_link = Some(
                    p.take_link(id)
                        .map_err(|e| anyhow::anyhow!("failed to take dae0_ingress link: {}", e))?,
                );
                info!("dae0_ingress attached and link held");
            }
            Err(e) => {
                warn!("dae0_ingress attach failed (non-fatal): {}", e);
            }
        }

        Ok(())
    }

    fn attach_dae0peer_ingress(&mut self) -> anyhow::Result<()> {
        // dae0peer lives in the daens namespace; enter it with a scoped
        // `with_daens_netns` switch for the attach (the process otherwise
        // stays in the host netns).  The netlink sockets used by
        // qdisc_add_clsact/attach_tc resolve interface names in the netns
        // they are created in, so both must run inside daens.  The link
        // handle persists after switching back to the host netns.
        crate::with_daens_netns("attach dae0peer_ingress", move || {
            if let Err(e) = aya::programs::tc::qdisc_add_clsact("dae0peer")
                && !e.to_string().contains("File exists")
            {
                warn!("failed to add clsact qdisc to dae0peer: {}", e);
            }

            match Self::attach_tc(self.bpf_mut()?, "dae0peer_ingress", "dae0peer") {
                Ok(id) => {
                    let p: &mut aya::programs::SchedClassifier = self
                        .bpf_mut()?
                        .program_mut("dae0peer_ingress")
                        .ok_or_else(|| anyhow::anyhow!("dae0peer_ingress program disappeared"))?
                        .try_into()?;
                    self.dae0peer_ingress_link = Some(p.take_link(id).map_err(|e| {
                        anyhow::anyhow!("failed to take dae0peer_ingress link: {}", e)
                    })?);
                    info!("dae0peer_ingress attached and link held");
                }
                Err(e) => {
                    warn!("dae0peer_ingress attach failed (non-fatal): {}", e);
                }
            }

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
        crate::with_daens_netns("attach tproxy_sk_lookup", move || {
            // FD-owned namespace handle (dup so the OnceLock FD stays put).
            let netns = crate::daens_fd()?
                .try_clone()
                .map_err(|e| anyhow::anyhow!("dup daens fd: {e}"))?;
            let p: &mut aya::programs::SkLookup = self
                .bpf_mut()?
                .program_mut("tproxy_sk_lookup")
                .ok_or_else(|| anyhow::anyhow!("tproxy_sk_lookup program not found"))?
                .try_into()?;
            p.load()
                .map_err(|e| anyhow::anyhow!("load tproxy_sk_lookup: {}", e))?;
            let id = p
                .attach(&netns)
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
        tcp6_fd: RawFd,
        udp4_fds: &[RawFd],
        udp6_fds: &[RawFd],
    ) -> anyhow::Result<()> {
        self.listeners_published = false;
        // Slot layout is part of the sk_lookup ABI: TCP4/TCP6, then four
        // UDP4 sockets and four UDP6 sockets.
        let mut entries = vec![(0u32, tcp4_fd), (1u32, tcp6_fd)];
        entries.extend(
            udp4_fds
                .iter()
                .enumerate()
                .map(|(index, fd)| (2 + index as u32, *fd)),
        );
        entries.extend(
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
                info!(fd, key, "Published listener socket to LISTEN_SOCKET_MAP");
            }
        }
        self.listeners_published = true;
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
        // Stop the DaeEvent ringbuf consumer as well; it owns the
        // EVENT_RINGBUF MapData taken out of the Ebpf object.
        if let Some(h) = self.event_flush_handle.take() {
            h.abort();
            let _ = h.await;
        }

        // Drop map fds before unlinking generation-owned pins. The persistent
        // allocator pin remains the sole owner across ordinary shutdown.
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
        let _ = self.remove_nonpersistent_pins();
    }
}

#[cfg(test)]
mod tests;
