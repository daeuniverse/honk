//! Native XDP publication. The root's mmap atomic is the kernel's final CAS frontier.

use crate::control::routing_matcher::codegen::{RoutingMapFds, emit_routing_program};
use crate::control::routing_matcher::{KernelPredicate, RoutingFactMaps, RoutingPushPlan};
use crate::xdp::host::sys::{Grace, bpf, memory_bytes};
use anyhow::{Context, ensure};
use honk_datapath::ScopeId;
pub(crate) use honk_ebpf_common::xdp::NativeReason;
use honk_ebpf_common::xdp::*;
pub(crate) use honk_ebpf_common::xdp::{NativeClaim, NativeKey};
use honk_ebpf_common::{DomainRouting, LpmKey};
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::topology::Topology;
use honk_xsk::{
    CapturedProgramConfig, CapturedPrograms, NativeProgramConfig, NativePrograms, NativeTarget,
    RetainedRxHandle, RxCompletion,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::mem::{offset_of, size_of};
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::NonNull;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};

mod host;
mod recording;
use host::{HostCandidate, HostPlanReservations, HostTarget, PreparedHostPlan};
#[cfg(test)]
pub(crate) use recording::NativeExportPublicationResult;
pub(crate) use recording::NativeExportResult;
use recording::{
    CapturedInventoryStatus, CapturedRealmCandidate, CapturedRealmState, CapturedReceipt,
    HookIdentity, Recording, Snapshot,
};

const PAGE_BYTES: usize = 4096;
const LPM_TRIE: u32 = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeClaimIdentity {
    pub(crate) key: NativeKey,
    pub(crate) epoch: u64,
    pub(crate) incarnation: u64,
    pub(crate) scope: u64,
}

impl NativeClaimIdentity {
    pub(crate) fn matches(&self, claim: &NativeClaim) -> bool {
        claim.is_transit(&self.key)
            && claim.epoch == self.epoch
            && claim.incarnation == self.incarnation
            && claim.scope == self.scope
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ImportedOriginal {
    pub(crate) identity: NativeClaimIdentity,
    pub(crate) producer: NativeImport,
    pub(crate) executor: u32,
    pub(crate) state: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OriginalExtent {
    pub(crate) frame_length: u32,
    pub(crate) l3_offset: u32,
    pub(crate) l3_length: u32,
    pub(crate) vlan_tci: [u16; 2],
    pub(crate) vlan_proto: [u16; 2],
    pub(crate) vlan_count: u16,
    pub(crate) inline_vlan_count: u16,
    pub(crate) dscp: u8,
}

pub(crate) struct NativeOriginal<'a> {
    pub(crate) imported: &'a ImportedOriginal,
    pub(crate) authority: CaptureAuthority,
    pub(crate) ingress: honk_datapath::forward::Ingress,
    pub(crate) facts: ScopeId,
    pub(crate) realm_index: u32,
    pub(crate) rx_queue: u32,
    pub(crate) extent: OriginalExtent,
    pub(crate) basis_epoch: u64,
    pub(crate) basis_flags: u32,
    pub(crate) retained_capture: bool,
    pub(crate) candidate: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeCaptureBasis {
    identity: NativeClaimIdentity,
    candidate: u64,
    basis_epoch: u64,
    routing_generation: u64,
    fingerprint: [u8; 32],
    mode_revision: u64,
    flags: u32,
    fact_scope: ScopeId,
    fact_revision: u64,
    fact_horizon: Option<tokio::time::Instant>,
    producer: NativeImport,
}

impl NativeCaptureBasis {
    pub(crate) fn new(
        original: &NativeOriginal<'_>,
        routing_generation: u64,
        fingerprint: [u8; 32],
        mode_revision: u64,
        stamp: (ScopeId, u64, Option<tokio::time::Instant>),
    ) -> Self {
        Self {
            identity: original.imported.identity,
            candidate: original.candidate,
            basis_epoch: original.basis_epoch,
            routing_generation,
            fingerprint,
            mode_revision,
            flags: original.basis_flags,
            fact_scope: stamp.0,
            fact_revision: stamp.1,
            fact_horizon: stamp.2,
            producer: original.imported.producer,
        }
    }
    pub(crate) fn identity(&self) -> NativeClaimIdentity {
        self.identity
    }
}

pub(crate) struct NativeBasis {
    capture: NativeCaptureBasis,
    producer: NativeImport,
    authority: CaptureAuthority,
    ingress: honk_datapath::forward::Ingress,
    realm_index: u32,
    rx_queue: u32,
    extent: OriginalExtent,
}

impl NativeBasis {
    pub(crate) fn new(original: &NativeOriginal<'_>, capture: NativeCaptureBasis) -> Self {
        Self {
            capture,
            producer: original.imported.producer,
            authority: original.authority,
            ingress: original.ingress,
            realm_index: original.realm_index,
            rx_queue: original.rx_queue,
            extent: original.extent,
        }
    }
    pub(crate) fn identity(&self) -> NativeClaimIdentity {
        self.capture.identity
    }
    pub(crate) fn producer(&self) -> NativeImport {
        self.producer
    }
    pub(crate) fn extent(&self) -> OriginalExtent {
        self.extent
    }
}

pub(crate) struct CaptureProof {
    candidate: u64,
    basis: NativeCaptureBasis,
}
impl CaptureProof {
    pub(crate) fn matches(&self, basis: &NativeCaptureBasis) -> bool {
        let expected = NativeCaptureBasis {
            candidate: self.basis.candidate,
            ..*basis
        };
        self.candidate != 0 && self.candidate == basis.candidate && self.basis == expected
    }
}
#[expect(
    clippy::large_enum_variant,
    reason = "First-consumer commit tokens stay on the stack; boxing would allocate per selection."
)]
pub(crate) enum CaptureCommit {
    Selected(CaptureProof),
    AlreadyCommitted,
}

pub(crate) struct PreparedOriginal {
    identity: NativeClaimIdentity,
    op_incarnation: u64,
    return_attachment: u64,
    expected_epoch: u64,
    expires_boottime_ns: u64,
}
impl PreparedOriginal {
    pub(crate) fn op_incarnation(&self) -> u64 {
        self.op_incarnation
    }
    pub(crate) fn return_attachment(&self) -> u64 {
        self.return_attachment
    }
    pub(crate) fn expires_boottime_ns(&self) -> u64 {
        self.expires_boottime_ns
    }
}

pub(crate) struct CapturedObservation {
    pub(crate) phase: u32,
    pub(crate) receipt: u32,
    pub(crate) entry_seq: u64,
}

struct CapturedMapping {
    root: OwnedFd,
    map: Map,
    mapping: NonNull<NativeCapturedOperation>,
    bytes: usize,
    attachment: ScopeId,
    _memory: MemoryReservation,
}
unsafe impl Send for CapturedMapping {}
unsafe impl Sync for CapturedMapping {}
impl CapturedMapping {
    fn phase(&self) -> &AtomicU32 {
        unsafe {
            &*self
                .mapping
                .as_ptr()
                .cast::<u8>()
                .add(offset_of!(NativeCapturedOperation, phase))
                .cast::<AtomicU32>()
        }
    }
}
impl Drop for CapturedMapping {
    fn drop(&mut self) {
        if unsafe { libc::munmap(self.mapping.as_ptr().cast(), self.bytes) } != 0 {
            tracing::error!(
                "captured operation munmap failed: {}",
                io::Error::last_os_error()
            );
        }
    }
}

#[derive(Clone)]
pub(crate) struct CapturedCell(Arc<CapturedMapping>);
impl CapturedCell {
    pub(crate) fn root_fd(&self) -> BorrowedFd<'_> {
        self.0.root.as_fd()
    }
    pub(crate) fn operation_fd(&self) -> BorrowedFd<'_> {
        self.0.map.fd.as_fd()
    }
    pub(crate) fn return_attachment(&self) -> ScopeId {
        self.0.attachment
    }
    pub(crate) fn observe(&self, prepared: &PreparedOriginal) -> io::Result<CapturedObservation> {
        let phase = self.0.phase().load(Ordering::Acquire);
        let record = self.0.mapping.as_ptr();
        let identity_matches = unsafe {
            std::ptr::addr_of!((*record).op_incarnation).read_volatile() == prepared.op_incarnation
                && std::ptr::addr_of!((*record).return_attachment).read_volatile()
                    == prepared.return_attachment
                && std::ptr::addr_of!((*record).key).read_volatile() == prepared.identity.key
                && std::ptr::addr_of!((*record).claim_epoch).read_volatile()
                    == prepared.identity.epoch
                && std::ptr::addr_of!((*record).claim_incarnation).read_volatile()
                    == prepared.identity.incarnation
                && std::ptr::addr_of!((*record).claim_scope).read_volatile()
                    == prepared.identity.scope
        };
        if !identity_matches {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "captured operation identity changed",
            ));
        }
        let receipt = unsafe { &*std::ptr::addr_of!((*record).receipt).cast::<AtomicU32>() }
            .load(Ordering::Acquire);
        let entry_seq = unsafe { &*std::ptr::addr_of!((*record).entry_seq).cast::<AtomicU64>() }
            .load(Ordering::Acquire);
        if phase != self.0.phase().load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "captured operation publication in progress",
            ));
        }
        Ok(CapturedObservation {
            phase,
            receipt,
            entry_seq,
        })
    }
}

struct CapturedBinding {
    cell: CapturedCell,
    programs: Option<Arc<CapturedPrograms>>,
    operation: Option<u64>,
    receipt: Option<CapturedReceipt>,
    grace_entry: u64,
    grace_done: u64,
    grace_recorded: bool,
    _inventory_memory: MemoryReservation,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OriginalInventory {
    pub(crate) held: usize,
    pub(crate) pending: usize,
    pub(crate) flight: bool,
    pub(crate) first_ordered: bool,
}

pub(crate) struct OriginalCompletion {
    port: RxCompletion,
    producer: NativeImport,
    outcome: u8,
    settled: bool,
    operation: [u64; 3],
}
impl OriginalCompletion {
    pub(crate) fn local(port: RxCompletion, producer: NativeImport, takeover: bool) -> Self {
        Self {
            port,
            producer,
            outcome: if takeover { 4 } else { 0 },
            settled: false,
            operation: [0; 3],
        }
    }
    pub(crate) fn returned(
        port: RxCompletion,
        producer: NativeImport,
        operation: [u64; 3],
        transferred: bool,
    ) -> Self {
        Self {
            port,
            producer,
            outcome: if transferred { 1 } else { 2 },
            settled: false,
            operation,
        }
    }
    pub(crate) fn handle(&self) -> RetainedRxHandle {
        self.port.handle()
    }
    #[cfg(test)]
    pub(crate) fn producer(&self) -> NativeImport {
        self.producer
    }
    pub(crate) fn into_port(self) -> io::Result<RxCompletion> {
        if !self.settled {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsettled Native completion",
            ));
        }
        Ok(self.port)
    }
}

fn settle_selection(
    claim: &mut NativeClaim,
    flags: u32,
    inventory: OriginalInventory,
) -> anyhow::Result<()> {
    ensure!(
        flags & !NATIVE_IMPORT_COUNTED == 0,
        "unknown original completion flags"
    );
    let count = claim.state >> 4;
    let next = if flags & NATIVE_IMPORT_COUNTED != 0 {
        count
            .checked_sub(1)
            .context("original redirect credit underflow")?
    } else {
        count
    };
    let phase = claim.state & 15;
    let next_phase = match (claim.executor, phase) {
        (NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED) => NATIVE_PHASE_CAPTURE_COMMITTED,
        (NATIVE_EXECUTOR_PENDING, NATIVE_PHASE_PENDING) => NATIVE_PHASE_PENDING,
        (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ARMED | NATIVE_PHASE_DRAINING) => {
            if inventory.first_ordered
                && next == 0
                && inventory.held == 0
                && inventory.pending == 0
                && !inventory.flight
            {
                NATIVE_PHASE_ACTIVE
            } else if inventory.first_ordered || phase == NATIVE_PHASE_DRAINING {
                NATIVE_PHASE_DRAINING
            } else {
                NATIVE_PHASE_ARMED
            }
        }
        (_, NATIVE_PHASE_CLOSING) => NATIVE_PHASE_CLOSING,
        _ => anyhow::bail!("completion cannot settle this Native selection"),
    };
    claim.state = (next << 4) | next_phase;
    Ok(())
}

fn original_horizon(producer: u64, installed: u64, now: u64) -> Option<u64> {
    let expires = producer.min(installed);
    (now < expires).then_some(expires)
}

fn original_receipt(
    identity: NativeClaimIdentity,
    producer: NativeImport,
    kind: &'static str,
) -> CapturedReceipt {
    CapturedReceipt {
        kind,
        key: Some(identity.key),
        claim_epoch: Some(identity.epoch),
        claim_incarnation: Some(identity.incarnation),
        claim_scope: Some(identity.scope),
        producer_epoch: Some(producer.epoch),
        producer_incarnation: Some(producer.incarnation),
        producer_expires_boottime_ns: Some(producer.expires_boottime_ns),
        producer_flags: Some(producer.flags),
        ..Default::default()
    }
}

fn basis_receipt(basis: &NativeCaptureBasis, state: &State, kind: &'static str) -> CapturedReceipt {
    let mut receipt = original_receipt(basis.identity, basis.producer, kind);
    receipt.basis_epoch = Some(basis.basis_epoch);
    receipt.routing_generation = Some(basis.routing_generation);
    receipt.routing_fingerprint = Some(basis.fingerprint);
    receipt.mode_revision = Some(basis.mode_revision);
    receipt.basis_flags = Some(basis.flags);
    receipt.fact_scope = Some(basis.fact_scope.as_u64());
    receipt.fact_revision = Some(basis.fact_revision);
    receipt.fact_horizon = state.scopes.get(&basis.fact_scope).map(|scope| {
        scope
            .facts
            .binary_search_by_key(&basis.identity.key.dst_ip, |fact| fact.0)
            .ok()
            .map_or(u64::MAX, |index| scope.facts[index].2)
    });
    receipt
}

struct Map {
    fd: OwnedFd,
    _memory: Vec<MemoryReservation>,
}
impl Map {
    fn allocation_bytes(kind: u32, key: usize, value: usize, count: u32) -> anyhow::Result<usize> {
        ensure!(count != 0, "zero native map capacity");
        if kind == LPM_TRIE {
            lpm_trie_bytes(key, value, count)
        } else {
            key.checked_add(value)
                .and_then(|n| n.checked_add(128))
                .and_then(|n| n.checked_mul(count as usize))
                .and_then(|n| n.checked_add(2 * PAGE_BYTES))
                .context("native map charge overflow")
        }
    }
    fn new(
        budget: &Arc<MemoryBudget>,
        kind: u32,
        key: usize,
        value: usize,
        count: u32,
        flags: u32,
    ) -> anyhow::Result<Self> {
        let charge = reserve(budget, Self::allocation_bytes(kind, key, value, count)?)?;
        Self::new_reserved(budget, kind, key, value, count, flags, charge)
    }
    fn new_reserved(
        budget: &Arc<MemoryBudget>,
        kind: u32,
        key: usize,
        value: usize,
        count: u32,
        flags: u32,
        charge: MemoryReservation,
    ) -> anyhow::Result<Self> {
        let bytes = Self::allocation_bytes(kind, key, value, count)?;
        ensure!(
            charge.bytes() >= bytes,
            "native map exceeds its prepared reservation"
        );
        #[repr(C)]
        struct Create {
            kind: u32,
            key: u32,
            value: u32,
            count: u32,
            flags: u32,
        }
        let fd = unsafe {
            OwnedFd::from_raw_fd(bpf(
                0,
                &mut Create {
                    kind,
                    key: key.try_into()?,
                    value: value.try_into()?,
                    count,
                    flags,
                },
            )?)
        };
        // Empty tries report zero and omit intermediate nodes/cache storage even when populated.
        let measured = if kind == LPM_TRIE {
            Ok(0)
        } else {
            memory_bytes(fd.as_fd())
        };
        let mut memory = vec![charge];
        let result = measured.and_then(|measured| {
            if measured > memory[0].bytes() {
                memory.push(reserve(budget, measured - memory[0].bytes())?);
            }
            Ok(())
        });
        if let Err(error) = result {
            for charge in memory {
                std::mem::forget(charge);
            }
            return Err(error);
        }
        Ok(Self {
            fd,
            _memory: memory,
        })
    }
    fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
    fn insert<K, V>(&self, key: &K, value: &V, flags: u64) -> io::Result<()> {
        element(
            2,
            self.fd(),
            key as *const K as u64,
            value as *const V as u64,
            flags,
        )
        .map(|_| ())
    }
    fn lookup<K, V: Default>(&self, key: &K) -> io::Result<Option<V>> {
        let mut value = V::default();
        match element(
            1,
            self.fd(),
            key as *const K as u64,
            &mut value as *mut V as u64,
            0,
        ) {
            Ok(_) => Ok(Some(value)),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn freeze(&self) -> anyhow::Result<()> {
        #[repr(C)]
        struct Freeze {
            fd: u32,
        }
        bpf(
            22,
            &mut Freeze {
                fd: self.fd() as u32,
            },
        )?;
        Ok(())
    }
    fn retire(self, memory: &mut Vec<MemoryReservation>) {
        let Self { fd, _memory } = self;
        drop(fd);
        memory.extend(_memory);
    }
}

fn lpm_trie_bytes(key: usize, value: usize, count: u32) -> anyhow::Result<usize> {
    ensure!(
        key == 20 && value == 32,
        "native LPM allocation layout changed"
    );
    let cpus = aya::util::nr_cpus().map_err(|(_, error)| error)?.get() as usize;
    ensure!(
        cpus <= 4096,
        "native possible CPU count exceeds allocation bound"
    );
    // Linux 6.12 requests 88-byte leaves/56-byte intermediates; 7.2.5 requests
    // 80 bytes including its allocator link for either kind (96-byte slab).
    // Two allocations per fill write also cover replacements waiting for RCU.
    let nodes = (count as usize)
        .checked_mul(2)
        .and_then(|n| n.checked_mul(128));
    // 7.2.5 memalloc.c: low=32, high=96, refill batch=48. Include a full
    // extra batch and one page per CPU for its cache/percpu metadata.
    let caches = cpus.checked_mul((96 + 48) * 128 + PAGE_BYTES);
    nodes
        .zip(caches)
        .and_then(|(nodes, caches)| nodes.checked_add(caches))
        .and_then(|n| n.checked_add(2 * PAGE_BYTES))
        .context("native LPM charge overflow")
}

fn reserve(budget: &Arc<MemoryBudget>, bytes: usize) -> anyhow::Result<MemoryReservation> {
    budget
        .reserve(bytes)
        .context("native shared memory budget exhausted")
}
fn element(command: u32, fd: RawFd, key: u64, value: u64, flags: u64) -> io::Result<i32> {
    #[repr(C)]
    struct Element {
        fd: u32,
        pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    bpf(
        command,
        &mut Element {
            fd: fd as u32,
            pad: 0,
            key,
            value,
            flags,
        },
    )
}

struct Root {
    map: Map,
    mapping: NonNull<u8>,
    bytes: usize,
    _memory: MemoryReservation,
}
// The mapping is shared only through aligned atomics, including with BPF cmpxchg.
unsafe impl Send for Root {}
unsafe impl Sync for Root {}
impl Root {
    fn new(budget: &Arc<MemoryBudget>) -> anyhow::Result<Self> {
        ensure!(
            size_of::<NativeRoot>() == 16
                && offset_of!(NativeRoot, epoch) == 0
                && offset_of!(NativeRoot, flags) == 8,
            "native root ABI differs"
        );
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        ensure!(page > 0, "native root page size unavailable");
        let bytes = page as usize;
        let memory = reserve(budget, bytes)?;
        let map = Map::new(budget, 2, 4, size_of::<NativeRoot>(), 1, 1 << 10)?;
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                map.fd(),
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        let root = Self {
            map,
            mapping: NonNull::new(pointer.cast()).context("null native root mapping")?,
            bytes,
            _memory: memory,
        };
        root.epoch().store(0, Ordering::SeqCst);
        root.flags().store(0, Ordering::SeqCst);
        Ok(root)
    }
    fn epoch(&self) -> &AtomicU64 {
        unsafe { &*self.mapping.as_ptr().cast::<AtomicU64>() }
    }
    fn flags(&self) -> &AtomicU32 {
        unsafe {
            &*self
                .mapping
                .as_ptr()
                .add(offset_of!(NativeRoot, flags))
                .cast::<AtomicU32>()
        }
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if unsafe { libc::munmap(self.mapping.as_ptr().cast(), self.bytes) } != 0 {
            tracing::error!("native root munmap failed: {}", io::Error::last_os_error());
        }
    }
}

struct Facts {
    maps: [Map; 5],
}
impl Facts {
    fn new(budget: &Arc<MemoryBudget>, facts: &RoutingFactMaps) -> anyhow::Result<Self> {
        Self::new_reserved(budget, facts, None)
    }
    fn new_reserved(
        budget: &Arc<MemoryBudget>,
        facts: &RoutingFactMaps,
        reservations: Option<[MemoryReservation; 5]>,
    ) -> anyhow::Result<Self> {
        let mut reservations = reservations.into_iter().flatten();
        let mut maps: [Option<Map>; 5] = std::array::from_fn(|_| None);
        let result = (|| -> anyhow::Result<()> {
            for (slot, entries) in maps.iter_mut().zip([
                &facts.destination_v4,
                &facts.destination_v6,
                &facts.source_v4,
                &facts.source_v6,
                &facts.mac,
            ]) {
                let count = u32::try_from(entries.len().max(1))?;
                let memory = match reservations.next() {
                    Some(memory) => memory,
                    None => reserve(
                        budget,
                        Map::allocation_bytes(
                            LPM_TRIE,
                            size_of::<LpmKey>(),
                            size_of::<DomainRouting>(),
                            count,
                        )?,
                    )?,
                };
                *slot = Some(Map::new_reserved(
                    budget,
                    LPM_TRIE,
                    size_of::<LpmKey>(),
                    size_of::<DomainRouting>(),
                    count,
                    1,
                    memory,
                )?);
                let map = slot.as_ref().expect("created Native fact map");
                for (key, value) in entries {
                    map.insert(key, value, 0)?;
                }
                map.freeze()?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            for map in maps.into_iter().flatten() {
                for charge in map._memory {
                    std::mem::forget(charge);
                }
            }
            return Err(error);
        }
        Ok(Self {
            maps: maps.map(|map| map.expect("all Native fact maps prepared")),
        })
    }
    fn fds(&self, domain: RawFd) -> RoutingMapFds {
        RoutingMapFds {
            destination_v4: self.maps[0].fd(),
            destination_v6: self.maps[1].fd(),
            source_v4: self.maps[2].fd(),
            source_v6: self.maps[3].fd(),
            mac: self.maps[4].fd(),
            domain,
        }
    }
}

struct Scope {
    revision: u64,
    generation: u64,
    fingerprint: [u8; 32],
    facts: Vec<([u32; 4], DomainRouting, u64, Option<tokio::time::Instant>)>,
    _memory: MemoryReservation,
}
impl Scope {
    fn matches(
        &self,
        revision: u64,
        generation: u64,
        fingerprint: [u8; 32],
        now: tokio::time::Instant,
        facts: impl Iterator<Item = (IpAddr, DomainRouting, Option<tokio::time::Instant>)>,
    ) -> bool {
        if self.revision != revision
            || self.generation != generation
            || self.fingerprint != fingerprint
        {
            return false;
        }
        let mut count = 0;
        let mut previous = None;
        for (ip, bitmap, expiry) in facts {
            if expiry.is_some_and(|expiry| expiry <= now) {
                continue;
            }
            let ip = ip.to_canonical();
            if count == self.facts.len() || previous.is_some_and(|previous| previous >= ip) {
                return false;
            }
            let key = super::maps::ip_addr_to_lpm_key(ip).data;
            let Ok(index) = self.facts.binary_search_by_key(&key, |entry| entry.0) else {
                return false;
            };
            if self.facts[index].1 != bitmap || self.facts[index].3 != expiry {
                return false;
            }
            previous = Some(ip);
            count += 1;
        }
        count == self.facts.len()
    }
}
struct Target {
    target: Arc<NativeTarget>,
    scope: ScopeId,
    active: Option<Candidate>,
    _memory: MemoryReservation,
    counters: ClosedCounters,
    hook_ids: [u64; 2],
    attachment_generation: u64,
}
struct Candidate {
    programs: NativePrograms,
    resources: CandidateResources,
}
struct CandidateResources {
    facts: Arc<Facts>,
    domain: Map,
    memory: MemoryReservation,
}
impl CandidateResources {
    fn retire(self, memory: &mut Vec<MemoryReservation>) {
        memory.push(self.memory);
        if let Some(facts) = Arc::into_inner(self.facts) {
            for map in facts.maps {
                map.retire(memory);
            }
        }
        self.domain.retire(memory);
    }
}

#[derive(Clone, Copy, Default)]
struct CounterGeneration {
    epoch: u64,
    related_seq: u64,
    operation_id: u64,
    live: bool,
}

struct ClosedCounters {
    map: Map,
    generations: [CounterGeneration; 256],
    _identity_memory: MemoryReservation,
    #[cfg(test)]
    test_cells: Option<Box<[NativeClosedCounterV1; 513]>>,
}

impl ClosedCounters {
    fn new(budget: &Arc<MemoryBudget>) -> anyhow::Result<Self> {
        ensure!(
            size_of::<NativeClosedCounterV1>() == 32
                && std::mem::align_of::<NativeClosedCounterV1>() == 8
                && offset_of!(NativeClosedCounterV1, epoch) == 0
                && offset_of!(NativeClosedCounterV1, ordinary_drops) == 8
                && offset_of!(NativeClosedCounterV1, overflow) == 16
                && offset_of!(NativeClosedCounterV1, reserved) == 24,
            "native closed counter ABI differs"
        );
        let memory = reserve(budget, (2 * PAGE_BYTES).max(size_of::<Self>()))?;
        let map = Map::new(budget, 2, 4, size_of::<NativeClosedCounterV1>(), 513, 0)?;
        map.insert(&512u32, &NativeClosedCounterV1::default(), 0)?;
        Ok(Self {
            map,
            generations: [CounterGeneration::default(); 256],
            _identity_memory: memory,
            #[cfg(test)]
            test_cells: None,
        })
    }

    fn insert_cell(&mut self, index: u32, value: NativeClosedCounterV1) -> anyhow::Result<()> {
        #[cfg(test)]
        if let Some(cells) = &mut self.test_cells {
            cells[index as usize] = value;
            return Ok(());
        }
        Ok(self.map.insert(&index, &value, 0)?)
    }

    fn cell(&self, index: u32) -> anyhow::Result<NativeClosedCounterV1> {
        #[cfg(test)]
        if let Some(cells) = &self.test_cells {
            return Ok(cells[index as usize]);
        }
        self.map
            .lookup(&index)?
            .context("native counter cell absent")
    }

    fn prepare(&mut self, epoch: u64, operation_id: u64, related_seq: u64) -> anyhow::Result<()> {
        let slot = ((epoch >> 1) & 255) as usize;
        ensure!(
            !self.generations[slot].live,
            "native counter generation is not sealed"
        );
        let value = NativeClosedCounterV1 {
            epoch,
            ..Default::default()
        };
        for hook in 0..2u32 {
            self.insert_cell(slot as u32 * 2 + hook, value)?;
        }
        self.generations[slot] = CounterGeneration {
            epoch,
            related_seq,
            operation_id,
            live: true,
        };
        Ok(())
    }

    fn seal(
        &mut self,
        current: Option<u64>,
        hook_ids: [u64; 2],
        recording: &mut Recording,
    ) -> anyhow::Result<()> {
        let result = (|| -> anyhow::Result<()> {
            for slot in 0..self.generations.len() {
                let generation = self.generations[slot];
                if !generation.live || Some(generation.epoch) == current {
                    continue;
                }
                for hook in 0..2u32 {
                    let value = self.cell(slot as u32 * 2 + hook)?;
                    ensure!(
                        value.is_valid(generation.epoch),
                        "native counter tag differs"
                    );
                    recording.counter_overflow |= value.overflow != 0;
                    let seq = recording.append(NativePublicationEventV1 {
                        operation_id: generation.operation_id,
                        related_seq: generation.related_seq,
                        counter_epoch: value.epoch,
                        counter_value: value.ordinary_drops,
                        hook_id: hook_ids[hook as usize],
                        kind: NATIVE_EVENT_CLOSED_COUNTS_FINAL,
                        outcome: NATIVE_OUTCOME_COMMITTED,
                        flags: NATIVE_EVENT_FLAG_COUNTER_VALID
                            | if value.overflow != 0 {
                                NATIVE_EVENT_FLAG_COUNTER_OVERFLOW
                            } else {
                                0
                            },
                        ..Default::default()
                    });
                    ensure!(seq != 0, "native final counter event was not recorded");
                }
                self.generations[slot].live = false;
            }
            let fault = self.cell(512)?;
            ensure!(
                fault == NativeClosedCounterV1::default(),
                "native closed counter accounting fault"
            );
            Ok(())
        })();
        if result.is_err() {
            recording.accounting_error = true;
        }
        result
    }
}
#[derive(Default)]
struct Writers {
    count: usize,
    failed: bool,
    terminal: bool,
}
impl Writers {
    fn begin(&mut self) -> anyhow::Result<()> {
        ensure!(
            !self.failed && !self.terminal,
            "native publication is permanently closed"
        );
        self.count = self
            .count
            .checked_add(1)
            .context("native writer count exhausted")?;
        Ok(())
    }
    fn finish(&mut self, committed: bool) -> bool {
        self.failed |= !committed;
        self.count -= 1;
        self.count == 0 && !self.failed && !self.terminal
    }
}
struct State {
    writers: Writers,
    ready: bool,
    capture_ready: bool,
    plan: Option<RoutingPushPlan>,
    _plan_memory: Option<MemoryReservation>,
    targets: Vec<Target>,
    hosts: Vec<HostTarget>,
    retired_hosts: Vec<HostCandidate>,
    host_preparation: Option<PreparedHostPlan>,
    scopes: HashMap<ScopeId, Scope>,
    captured: Option<CapturedBinding>,
    captured_inventory_dirty: bool,
    clock_offset: (i128, i128),
    retired: Vec<Candidate>,
    failed_resources: Vec<CandidateResources>,
    retired_memory: Vec<MemoryReservation>,
    recording: Recording,
    current_closed_seq: u64,
    current_closed_operation: u64,
    next_hook_id: u64,
    operation_context: (u64, u64, NativeReason),
    #[cfg(test)]
    test_can_open: bool,
}

/// One optional owner for a Native-configured userspace backend.
pub struct NativePublication {
    root: Root,
    claims: Map,
    scratch: Map,
    import_failed: AtomicBool,
    import_close_pending: AtomicBool,
    grace: Grace,
    budget: Arc<MemoryBudget>,
    state: Mutex<State>,
    capacity: u32,
    monotonic_offset_ns: i128,
    _memory: Vec<MemoryReservation>,
    #[cfg(test)]
    test_closed: bool,
    #[cfg(test)]
    write_attempts: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    test_grace: std::sync::atomic::AtomicU8,
    #[cfg(test)]
    test_grace_observed_epoch: AtomicU64,
}

pub(crate) struct HostPlanPreparation {
    publication: Arc<NativePublication>,
    reservation: Option<HostPlanReservations>,
    owner: Option<u64>,
}
/// An admitted writer owns closure through its last committed sibling's drop.
pub(crate) struct NativeWrite {
    publication: Arc<NativePublication>,
    epoch: u64,
    committed: bool,
    writer_id: u64,
    operation_id: u64,
    reason: NativeReason,
    host_preparation: Option<u64>,
}
impl Drop for NativeWrite {
    fn drop(&mut self) {
        let mut state = self.publication.state.lock();
        if state
            .host_preparation
            .as_ref()
            .is_some_and(|prepared| prepared.writer_id == self.writer_id)
        {
            state.host_preparation = None;
        }
        let last = state.writers.finish(self.committed);
        let deferral = state.deferral();
        state.recording.append(NativePublicationEventV1 {
            operation_id: self.operation_id,
            writer_id: self.writer_id,
            epoch_after: self.publication.root.epoch().load(Ordering::SeqCst),
            kind: NATIVE_EVENT_WRITER_OUTCOME,
            reason: self.reason as u32,
            outcome: if self.committed {
                NATIVE_OUTCOME_COMMITTED
            } else {
                NATIVE_OUTCOME_FAILED
            },
            flags: deferral,
            ..Default::default()
        });
        if state.captured_inventory_dirty
            && let Err(error) =
                self.publication
                    .record_captured_inventory(&mut state, self.epoch, self.committed)
        {
            state.recording.accounting_error = true;
            state.writers.failed = true;
            tracing::error!(%error, "Native captured candidate inventory did not publish");
        }
        if last
            && !self.publication.import_failed.load(Ordering::Acquire)
            && state.can_open()
            && !state.recording.recording_error
            && !state.recording.clock_error
            && !state.recording.accounting_error
        {
            let epoch = self.publication.root.epoch().load(Ordering::SeqCst);
            if let Some(open) = epoch.checked_add(1).filter(|epoch| *epoch < u64::MAX) {
                self.publication.store_recorded(
                    &mut state,
                    open,
                    self.operation_id,
                    self.writer_id,
                    self.reason,
                    true,
                );
                if state.writers.failed
                    || state.recording.recording_error
                    || state.recording.clock_error
                {
                    let closed = open + 1;
                    let operation = state.recording.operation();
                    let _ = self.publication.close_recorded(
                        &mut state,
                        closed,
                        operation,
                        self.writer_id,
                        NativeReason::AccountingFailure,
                        true,
                    );
                }
            } else {
                state.writers.failed = true;
                let _ = self.publication.close_recorded(
                    &mut state,
                    epoch & !1,
                    self.operation_id,
                    self.writer_id,
                    NativeReason::EpochExhaustion,
                    true,
                );
            }
        }
    }
}
impl NativeWrite {
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    #[cfg(test)]
    pub(crate) fn writer_id_for_test(&self) -> u64 {
        self.writer_id
    }
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}
impl State {
    fn retain_kernel_charges(&mut self) {
        for target in &mut self.targets {
            if let Some(candidate) = target.active.take() {
                drop(candidate.programs);
                candidate.resources.retire(&mut self.retired_memory);
            }
            for charge in target.counters.map._memory.drain(..) {
                std::mem::forget(charge);
            }
        }
        self.finish_retirement();
        for resources in self.failed_resources.drain(..) {
            resources.retire(&mut self.retired_memory);
        }
        for charge in self.retired_memory.drain(..) {
            std::mem::forget(charge);
        }
    }
    fn finish_retirement(&mut self) {
        // Closed FDs have no kernel reclamation ACK; retain every retired charge.
        self.retired_hosts.clear();
        for candidate in self.retired.drain(..) {
            drop(candidate.programs);
            candidate.resources.retire(&mut self.retired_memory);
        }
    }
    fn deferral(&self) -> u32 {
        if self.writers.count != 0 {
            return NATIVE_EVENT_FLAG_OTHER_WRITERS;
        }
        if !self.ready {
            return NATIVE_EVENT_FLAG_NOT_READY;
        }
        if !self.capture_ready {
            return NATIVE_EVENT_FLAG_CAPTURE_NOT_READY;
        }
        if self.plan.is_none() {
            return NATIVE_EVENT_FLAG_MISSING_PLAN;
        }
        if self.targets.is_empty() && self.hosts.is_empty() {
            return NATIVE_EVENT_FLAG_MISSING_TARGET;
        }
        if !self.can_open() {
            return NATIVE_EVENT_FLAG_MISSING_SCOPE;
        }
        0
    }
    fn can_open(&self) -> bool {
        #[cfg(test)]
        if self.test_can_open {
            return true;
        }
        self.ready
            && self.capture_ready
            && (self.targets.is_empty()
                || self
                    .captured
                    .as_ref()
                    .is_some_and(|binding| binding.programs.is_some()))
            && self.plan.as_ref().is_some_and(|plan| {
                (!self.targets.is_empty() || !self.hosts.is_empty())
                    && self.hosts.iter().all(|host| host.active.is_some())
                    && (self.hosts.is_empty()
                        || self
                            .scopes
                            .get(&ScopeId::HOST)
                            .is_some_and(|scope| scope.fingerprint == plan.policy_fingerprint))
                    && self.targets.iter().all(|target| {
                        target.active.is_some()
                            && self
                                .scopes
                                .get(&target.scope)
                                .is_some_and(|scope| scope.fingerprint == plan.policy_fingerprint)
                    })
            })
    }
}

impl NativePublication {
    fn record_captured_inventory(
        &self,
        state: &mut State,
        epoch: u64,
        committed: bool,
    ) -> anyhow::Result<()> {
        let Some(binding) = state.captured.as_ref() else {
            return Ok(());
        };
        let Some(programs) = binding.programs.as_ref().cloned() else {
            return Ok(());
        };
        let attachment = binding.cell.return_attachment().as_u64();
        let inventory = programs.realm_gate_inventory();
        ensure!(
            inventory.len() <= 128,
            "captured retained realm inventory exceeds bound"
        );
        let mut selected = [0u32; 64];
        let mut count = 0;
        for target in &state.targets {
            if let Some(gate) = target
                .active
                .as_ref()
                .and_then(|candidate| candidate.programs.captured_gate())
            {
                ensure!(
                    count < selected.len(),
                    "captured selected realm inventory exceeds bound"
                );
                selected[count] = gate.resource.id;
                count += 1;
            }
        }
        selected[..count].sort_unstable();
        let status = if committed {
            CapturedInventoryStatus::Committed
        } else if inventory.iter().any(|gate| gate.closed_epoch >= epoch) {
            CapturedInventoryStatus::Partial
        } else {
            CapturedInventoryStatus::Failed
        };
        state.recording.captured_inventory(
            attachment,
            status,
            inventory
                .iter()
                .filter(|gate| gate.resource.state != honk_xsk::CapturedResourceState::Unpinned)
                .map(|gate| CapturedRealmCandidate {
                    pin_path: &gate.resource.pin_path,
                    program_id: gate.resource.id,
                    realm_index: gate.realm_index,
                    closed_epoch: gate.closed_epoch,
                    state: if selected[..count].binary_search(&gate.resource.id).is_ok() {
                        CapturedRealmState::Installed
                    } else {
                        CapturedRealmState::RetiredPending
                    },
                }),
        )?;
        let snapshot = self.recording_snapshot(state, false);
        let result = state.recording.export(false, snapshot);
        result.record();
        if let Some(error) = result.error {
            return Err(error);
        }
        ensure!(
            result.status == recording::NativeExportPublicationResult::PublishedDurable,
            "captured canonical inventory was not durably published"
        );
        state.captured_inventory_dirty = false;
        Ok(())
    }

    pub(crate) fn acknowledge_captured_join(
        &self,
        attachment: u64,
        path: &std::path::Path,
        sha256: [u8; 32],
    ) -> anyhow::Result<()> {
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("captured joined receipt filename")?;
        let mut state = self.state.lock();
        ensure!(
            state.writers.terminal && self.root.epoch().load(Ordering::Acquire) & 1 == 0,
            "captured joined acknowledgment requires terminal closure"
        );
        state
            .recording
            .captured_joined_ack(attachment, filename, sha256)?;
        let snapshot = self.recording_snapshot(&state, false);
        let result = state.recording.export(false, snapshot);
        result.record();
        if let Some(error) = result.error {
            state.recording.accounting_error = true;
            return Err(error);
        }
        if result.status != recording::NativeExportPublicationResult::PublishedDurable {
            state.recording.accounting_error = true;
            anyhow::bail!("captured joined acknowledgment was not durably published");
        }
        Ok(())
    }

    pub(crate) fn create_captured_cell(
        self: &Arc<Self>,
        writer: &NativeWrite,
    ) -> anyhow::Result<CapturedCell> {
        self.change(writer, NativeReason::Startup, |state| {
            ensure!(
                state.captured.is_none(),
                "captured operation already allocated"
            );
            let attachment = ScopeId::allocate().context("captured return attachment exhausted")?;
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            ensure!(
                page > 0 && size_of::<NativeCapturedOperation>() == 264,
                "captured operation layout differs"
            );
            let bytes =
                size_of::<NativeCapturedOperation>().div_ceil(page as usize) * page as usize;
            let memory = reserve(&self.budget, bytes)?;
            let inventory_bytes = 128usize
                .checked_mul(size_of::<honk_xsk::CapturedGateIdentity>() + 4096)
                .and_then(|bytes| bytes.checked_add(4 * PAGE_BYTES))
                .context("captured inventory scratch overflow")?;
            let inventory_memory = reserve(&self.budget, inventory_bytes)?;
            let map = Map::new(
                &self.budget,
                2,
                4,
                size_of::<NativeCapturedOperation>(),
                1,
                1 << 10,
            )?;
            let root = self.root.map.fd.try_clone()?;
            let pointer = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    bytes,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    map.fd(),
                    0,
                )
            };
            if pointer == libc::MAP_FAILED {
                return Err(io::Error::last_os_error().into());
            }
            let cell = CapturedCell(Arc::new(CapturedMapping {
                root,
                map,
                mapping: NonNull::new(pointer.cast()).context("null operation mapping")?,
                bytes,
                attachment,
                _memory: memory,
            }));
            cell.0.phase().store(NATIVE_OP_IDLE, Ordering::Release);
            state.captured = Some(CapturedBinding {
                cell: cell.clone(),
                programs: None,
                operation: None,
                receipt: None,
                grace_entry: 0,
                grace_done: 0,
                grace_recorded: false,
                _inventory_memory: inventory_memory,
            });
            Ok(cell)
        })
    }

    pub(crate) fn register_captured(
        self: &Arc<Self>,
        cell: &CapturedCell,
        programs: Arc<CapturedPrograms>,
        writer: &NativeWrite,
    ) -> anyhow::Result<()> {
        self.change(writer, NativeReason::Startup, |state| {
            let binding = state
                .captured
                .as_ref()
                .context("captured operation not allocated")?;
            ensure!(
                Arc::ptr_eq(&binding.cell.0, &cell.0) && binding.programs.is_none(),
                "captured cell binding changed"
            );
            ensure!(
                programs.return_attachment() == cell.return_attachment().as_u64()
                    && programs.root_map_id() == crate::xdp::host::sys::identity(cell.root_fd())?.1
                    && programs.operation_map_id()
                        == crate::xdp::host::sys::identity(cell.operation_fd())?.1,
                "captured map or attachment identity differs"
            );
            ensure!(
                programs.targets().len() == state.targets.len(),
                "captured target inventory differs"
            );
            for (index, (registered, loaded)) in
                state.targets.iter().zip(programs.targets()).enumerate()
            {
                ensure!(
                    loaded.realm_index as usize == index
                        && loaded.logical_ifindex == registered.target.capture().authority.ifindex
                        && Arc::ptr_eq(&registered.target, &loaded.target),
                    "captured target was not registered"
                );
            }
            programs.check()?;
            state.captured.as_mut().unwrap().programs = Some(programs);
            state.captured_inventory_dirty = true;
            if let Some(plan) = state.plan.take() {
                let result = self.publish_candidates(state, &plan, None);
                state.plan = Some(plan);
                result?;
            }
            Ok(())
        })
    }

    pub(crate) fn original_epoch_is_open(&self, prepared: &PreparedOriginal) -> bool {
        self.root.epoch().load(Ordering::Acquire) == prepared.expected_epoch
    }

    pub(crate) fn original_grace(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock();
        let flight = state
            .captured
            .as_ref()
            .filter(|binding| !binding.grace_recorded)
            .and_then(|binding| {
                binding.receipt.map(|receipt| {
                    (
                        binding.operation,
                        receipt,
                        binding.cell.0.phase().load(Ordering::Acquire),
                        unsafe {
                            &*std::ptr::addr_of!((*binding.cell.0.mapping.as_ptr()).entry_seq)
                                .cast::<AtomicU64>()
                        }
                        .load(Ordering::Acquire),
                    )
                })
            });
        let mut start = 0;
        let mut operation = None;
        let mut entry = 0;
        let mut template = None;
        if let Some((Some(op), mut receipt, phase, entry_seq)) = flight
            && matches!(phase, NATIVE_OP_ENTERED | NATIVE_OP_GATE_REFUSED)
        {
            state.captured.as_mut().unwrap().grace_recorded = true;
            operation = Some(op);
            entry = entry_seq;
            receipt.entry_seq = (phase == NATIVE_OP_ENTERED).then_some(entry_seq);
            if phase == NATIVE_OP_ENTERED {
                ensure!(entry_seq != 0, "captured entry sequence absent");
                receipt.kind = "ENTRY_ACQUIRED";
                receipt.boottime_ns = Some(clock_ns(libc::CLOCK_BOOTTIME)?);
                receipt.related_seq = None;
                let observed = state.recording.captured(receipt);
                receipt.related_seq = Some(observed);
            }
            receipt.kind = "FRESH_GRACE_STARTED";
            receipt.boottime_ns = Some(clock_ns(libc::CLOCK_BOOTTIME)?);
            start = state.recording.captured(receipt);
            template = Some(receipt);
        }
        drop(state);
        let result = self.reader_grace();
        if let Some(mut receipt) = template {
            let mut state = self.state.lock();
            ensure!(
                state
                    .captured
                    .as_ref()
                    .is_some_and(|binding| binding.operation == operation),
                "original changed during fresh grace"
            );
            receipt.kind = "FRESH_GRACE_DONE";
            receipt.related_seq = Some(start);
            receipt.fresh_grace = Some(result.is_ok());
            receipt.boottime_ns = Some(clock_ns(libc::CLOCK_BOOTTIME)?);
            let done = state.recording.captured(receipt);
            if result.is_ok() {
                let binding = state.captured.as_mut().unwrap();
                binding.grace_entry = entry;
                binding.grace_done = done;
            }
        }
        if result.is_ok()
            && self.state.lock().captured.as_ref().is_some_and(|binding| {
                binding.operation.is_some() && binding.grace_recorded && binding.grace_done == 0
            })
        {
            anyhow::bail!("captured original first completion grace failed; retaining ownership");
        }
        result
    }

    pub(crate) fn prepare_original(
        self: &Arc<Self>,
        cell: &CapturedCell,
        basis: &NativeBasis,
    ) -> anyhow::Result<PreparedOriginal> {
        let writer = self.write(NativeReason::RuntimeMaintenance)?;
        let mut expired = false;
        let result = self.change(&writer, NativeReason::RuntimeMaintenance, |state| {
            if !self.basis_is_current(state, &writer, &basis.capture) {
                return Ok(None);
            }
            let binding = state
                .captured
                .as_ref()
                .context("captured operation not registered")?;
            ensure!(
                Arc::ptr_eq(&binding.cell.0, &cell.0),
                "foreign captured operation cell"
            );
            binding
                .programs
                .as_ref()
                .context("captured programs not registered")?
                .check()?;
            let phase = cell.0.phase().load(Ordering::Acquire);
            if binding.operation.is_some() && phase != NATIVE_OP_PREPARED {
                return Ok(None);
            }
            let claim = self
                .claims
                .lookup::<_, NativeClaim>(&basis.capture.identity.key)?
                .context("original claim absent")?;
            ensure!(
                basis.capture.identity.matches(&claim),
                "original claim changed"
            );
            if !matches!(
                (claim.executor, claim.state & 15),
                (NATIVE_EXECUTOR_PENDING, NATIVE_PHASE_PENDING)
                    | (
                        NATIVE_EXECUTOR_KERNEL,
                        NATIVE_PHASE_ARMED | NATIVE_PHASE_DRAINING
                    )
            ) {
                return Ok(None);
            }
            ensure!(
                basis.producer.flags == NATIVE_IMPORT_COUNTED && claim.state >> 4 != 0,
                "original return lacks producer credit"
            );
            let target = state
                .targets
                .get(basis.realm_index as usize)
                .context("original realm absent")?;
            ensure!(
                target.scope.as_u64() == basis.capture.identity.scope
                    && target.target.capture().authority == basis.authority
                    && basis.ingress.namespace == basis.authority.namespace_cookie
                    && basis.ingress.attachment == basis.authority.attachment_generation
                    && basis.ingress.ifindex == basis.authority.ifindex
                    && basis.rx_queue < target.target.queues(),
                "original ingress authority differs"
            );
            let scope = state
                .scopes
                .get(&basis.capture.fact_scope)
                .context("original fact scope absent")?;
            let fact_horizon = scope
                .facts
                .binary_search_by_key(&basis.capture.identity.key.dst_ip, |fact| fact.0)
                .ok()
                .map_or(u64::MAX, |index| scope.facts[index].2);
            let Some(expires) = original_horizon(
                basis.producer.expires_boottime_ns,
                fact_horizon,
                clock_ns(libc::CLOCK_BOOTTIME)?,
            ) else {
                expired = true;
                return Ok(None);
            };
            let expected_epoch = writer
                .epoch
                .checked_add(1)
                .filter(|epoch| *epoch < u64::MAX)
                .context("original epoch exhausted")?;
            let extent = basis.extent;
            let record = NativeCapturedOperation {
                op_incarnation: writer.epoch,
                return_attachment: cell.return_attachment().as_u64(),
                ingress_attachment: basis.authority.attachment_generation,
                claim_epoch: basis.capture.identity.epoch,
                claim_incarnation: basis.capture.identity.incarnation,
                claim_scope: basis.capture.identity.scope,
                capture_epoch: basis.producer.epoch,
                basis_epoch: expected_epoch,
                expires_boottime_ns: expires,
                routing_generation: basis.capture.routing_generation,
                mode_revision: basis.capture.mode_revision,
                fact_scope: basis.capture.fact_scope.as_u64(),
                fact_revision: basis.capture.fact_revision,
                fact_horizon,
                key: basis.capture.identity.key,
                ingress_ifindex: basis.authority.ifindex,
                logical_ifindex: basis.ingress.ifindex,
                realm_index: basis.realm_index,
                frame_length: extent.frame_length,
                l3_offset: extent.l3_offset,
                l3_length: extent.l3_length,
                flags: basis.producer.flags,
                vlan_tci: extent.vlan_tci,
                vlan_proto: extent.vlan_proto,
                vlan_count: extent.vlan_count,
                inline_vlan_count: extent.inline_vlan_count,
                dscp: extent.dscp,
                rx_queue: basis.rx_queue,
                ..Default::default()
            };
            // The writer has joined every old private reader before replacing immutable fields.
            unsafe {
                cell.0.mapping.as_ptr().write_volatile(record);
            }
            cell.0.phase().store(NATIVE_OP_PREPARED, Ordering::Release);
            let mut receipt = basis_receipt(&basis.capture, state, "OPERATION_PREPARED");
            receipt.basis_epoch = Some(expected_epoch);
            receipt.return_attachment = Some(cell.return_attachment().as_u64());
            receipt.slot = Some(0);
            receipt.op_incarnation = Some(writer.epoch);
            receipt.fact_horizon = Some(fact_horizon);
            receipt.boottime_ns = Some(clock_ns(libc::CLOCK_BOOTTIME)?);
            let seq = state.recording.captured(receipt);
            receipt.seq = seq;
            let binding = state.captured.as_mut().unwrap();
            binding.operation = Some(writer.epoch);
            binding.receipt = Some(receipt);
            binding.grace_entry = 0;
            binding.grace_done = 0;
            binding.grace_recorded = false;
            Ok(Some(PreparedOriginal {
                identity: basis.capture.identity,
                op_incarnation: writer.epoch,
                return_attachment: cell.return_attachment().as_u64(),
                expected_epoch,
                expires_boottime_ns: expires,
            }))
        });
        match result {
            Ok(prepared) => {
                writer.commit();
                prepared.ok_or_else(|| {
                    if expired {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "captured original producer horizon expired",
                        )
                        .into()
                    } else {
                        io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "original basis or operation busy",
                        )
                        .into()
                    }
                })
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn finish_original(
        self: &Arc<Self>,
        expected: &NativeClaimIdentity,
        completion: &mut OriginalCompletion,
        mut inventory: OriginalInventory,
    ) -> anyhow::Result<NativeClaim> {
        if self.state.lock().writers.terminal {
            let mut state = self.state.lock();
            self.drain_recorded(&mut state, NativeReason::Shutdown)?;
            inventory.first_ordered = false;
            let result = self.finish_original_locked(&mut state, expected, completion, inventory);
            if result.is_err() {
                state.writers.failed = true;
            }
            return result;
        }
        let writer = self.write(NativeReason::RuntimeMaintenance)?;
        let result = self.change(&writer, NativeReason::RuntimeMaintenance, |state| {
            self.finish_original_locked(state, expected, completion, inventory)
        });
        if result.is_ok() {
            writer.commit();
        }
        result
    }

    fn finish_original_locked(
        &self,
        state: &mut State,
        expected: &NativeClaimIdentity,
        completion: &mut OriginalCompletion,
        inventory: OriginalInventory,
    ) -> anyhow::Result<NativeClaim> {
        ensure!(
            !completion.settled && completion.producer.flags & !NATIVE_IMPORT_COUNTED == 0,
            "Native completion replay or invalid producer"
        );
        ensure!(
            matches!(completion.outcome, 0 | 1 | 2 | 4),
            "ambiguous or invalid completion cannot settle ownership"
        );
        ensure!(
            completion.producer.incarnation == expected.incarnation
                && completion.producer.epoch >= expected.epoch
                && completion.producer.epoch & 1 != 0
                && completion.producer.expires_boottime_ns != 0
                && completion.producer.reserved == 0,
            "completion producer does not own this claim"
        );
        let mut claim = self
            .claims
            .lookup::<_, NativeClaim>(&expected.key)?
            .context("completion claim absent")?;
        ensure!(
            expected.matches(&claim),
            "completion claim identity changed"
        );
        let operation = matches!(completion.outcome, 1 | 2);
        let mut receipt = original_receipt(*expected, completion.producer, "ORIGINAL_FINISHED");
        if operation {
            let binding = state
                .captured
                .as_ref()
                .context("completion operation absent")?;
            ensure!(
                binding.operation == Some(completion.operation[0])
                    && binding.cell.return_attachment().as_u64() == completion.operation[1],
                "completion operation identity changed"
            );
            let phase = binding.cell.0.phase().load(Ordering::Acquire);
            ensure!(
                binding.grace_done != 0 && binding.grace_entry == completion.operation[2],
                "completion lacks matching fresh grace"
            );
            if completion.outcome == 1 {
                let entry_seq = unsafe {
                    &*std::ptr::addr_of!((*binding.cell.0.mapping.as_ptr()).entry_seq)
                        .cast::<AtomicU64>()
                }
                .load(Ordering::Acquire);
                ensure!(
                    phase == NATIVE_OP_ENTERED
                        && completion.operation[2] != 0
                        && entry_seq == completion.operation[2],
                    "return completion lacks matching entry and fresh grace"
                );
            } else {
                ensure!(
                    phase == NATIVE_OP_GATE_REFUSED && completion.operation[2] == 0,
                    "refused operation may have transferred"
                );
            }
            receipt = binding.receipt.context("operation receipt absent")?;
            ensure!(
                receipt.key == Some(expected.key)
                    && receipt.claim_epoch == Some(expected.epoch)
                    && receipt.claim_incarnation == Some(expected.incarnation)
                    && receipt.claim_scope == Some(expected.scope)
                    && receipt.producer_epoch == Some(completion.producer.epoch)
                    && receipt.producer_incarnation == Some(completion.producer.incarnation)
                    && receipt.producer_expires_boottime_ns
                        == Some(completion.producer.expires_boottime_ns)
                    && receipt.producer_flags == Some(completion.producer.flags),
                "private completion belongs to another claim or producer"
            );
            receipt.kind = "ORIGINAL_FINISHED";
            receipt.entry_seq = (completion.operation[2] != 0).then_some(completion.operation[2]);
            receipt.fresh_grace = Some(true);
            receipt.related_seq = Some(binding.grace_done);
        }
        receipt.inventory_held = Some(u64::try_from(inventory.held)?);
        receipt.inventory_pending = Some(u64::try_from(inventory.pending)?);
        receipt.inventory_flight = Some(u64::from(inventory.flight));
        receipt.count_before = Some(u64::from(claim.state >> 4));
        settle_selection(&mut claim, completion.producer.flags, inventory)?;
        receipt.count_after = Some(u64::from(claim.state >> 4));
        receipt.phase_after = Some(claim.state & 15);
        receipt.terminal = Some(state.writers.terminal);
        receipt.boottime_ns = Some(clock_ns(libc::CLOCK_BOOTTIME)?);
        self.claims.insert(&expected.key, &claim, 2)?;
        let handle = completion.port.handle().receipt_identity();
        receipt.completion_handle = Some([
            handle.port,
            handle.port_generation,
            handle.slot,
            handle.slot_generation,
        ]);
        receipt.outcome = Some(match completion.outcome {
            1 => "Transferred",
            2 => "RefusedBeforeTransfer",
            4 => "TakenOver",
            _ => "Disposed",
        });
        state.recording.captured(receipt);
        completion.settled = true;
        if operation {
            state.captured.as_mut().unwrap().operation = None;
        }
        Ok(claim)
    }

    pub(crate) fn record_imported(
        &self,
        identity: NativeClaimIdentity,
        producer: NativeImport,
        handle: RetainedRxHandle,
    ) {
        let mut receipt = original_receipt(identity, producer, "IMPORTED");
        let handle = handle.receipt_identity();
        receipt.completion_handle = Some([
            handle.port,
            handle.port_generation,
            handle.slot,
            handle.slot_generation,
        ]);
        receipt.boottime_ns = clock_ns(libc::CLOCK_BOOTTIME).ok();
        self.state.lock().recording.captured(receipt);
    }

    pub(crate) fn record_ambiguous(
        &self,
        identity: NativeClaimIdentity,
        producer: NativeImport,
        handle: RetainedRxHandle,
        operation: [u64; 3],
    ) {
        let mut state = self.state.lock();
        let mut receipt = state
            .captured
            .as_ref()
            .filter(|binding| binding.operation == Some(operation[0]))
            .and_then(|binding| binding.receipt)
            .unwrap_or_else(|| original_receipt(identity, producer, "ORIGINAL_FINISHED"));
        receipt.kind = "ORIGINAL_FINISHED";
        let handle = handle.receipt_identity();
        receipt.completion_handle = Some([
            handle.port,
            handle.port_generation,
            handle.slot,
            handle.slot_generation,
        ]);
        receipt.outcome = Some("Ambiguous");
        receipt.entry_seq = (operation[2] != 0).then_some(operation[2]);
        receipt.boottime_ns = clock_ns(libc::CLOCK_BOOTTIME).ok();
        state.recording.captured(receipt);
    }
    pub(crate) fn check_original_selection(&self) -> anyhow::Result<()> {
        let state = self.state.lock();
        ensure!(
            !self.import_failed.load(Ordering::Acquire)
                && !state.writers.failed
                && !state.writers.terminal
                && !state.recording.recording_error
                && !state.recording.clock_error
                && !state.recording.accounting_error,
            "Native original selection is permanently closed"
        );
        Ok(())
    }

    pub(crate) fn selection_snapshot(&self) -> Option<(u64, u32)> {
        if self.import_failed.load(Ordering::Acquire) {
            return None;
        }
        let epoch = self.root.epoch().load(Ordering::Acquire);
        if epoch == 0 || epoch & 1 == 0 {
            return None;
        }
        let flags = self.root.flags().load(Ordering::Acquire);
        (self.root.epoch().load(Ordering::Acquire) == epoch).then_some((epoch, flags))
    }

    pub(crate) fn selection_epoch(&self) -> Option<u64> {
        self.selection_snapshot().map(|snapshot| snapshot.0)
    }

    fn basis_is_current(
        &self,
        state: &State,
        writer: &NativeWrite,
        basis: &NativeCaptureBasis,
    ) -> bool {
        if basis.candidate == 0
            || basis.basis_epoch.checked_add(1) != Some(writer.epoch)
            || self.root.epoch().load(Ordering::Acquire) != writer.epoch
            || state.writers.count != 1
            || basis.flags != self.root.flags().load(Ordering::Acquire)
            || basis
                .fact_horizon
                .is_some_and(|expiry| tokio::time::Instant::now() >= expiry)
        {
            return false;
        }
        let Some(plan) = &state.plan else {
            return false;
        };
        let Some(scope) = state.scopes.get(&basis.fact_scope) else {
            return false;
        };
        plan.policy_fingerprint == basis.fingerprint
            && scope.fingerprint == basis.fingerprint
            && scope.generation == basis.routing_generation
            && scope.revision == basis.fact_revision
            && scope
                .facts
                .binary_search_by_key(&basis.identity.key.dst_ip, |fact| fact.0)
                .ok()
                .map_or(basis.fact_horizon.is_none(), |index| {
                    scope.facts[index].3 == basis.fact_horizon
                })
    }

    pub(crate) fn commit_capture(
        self: &Arc<Self>,
        expected: &NativeClaimIdentity,
        basis: &NativeCaptureBasis,
    ) -> anyhow::Result<CaptureCommit> {
        let writer = self.write(NativeReason::RuntimeMaintenance)?;
        let result = self.change(&writer, NativeReason::RuntimeMaintenance, |state| {
            if basis.identity() != *expected || !self.basis_is_current(state, &writer, basis) {
                return Ok(None);
            }
            let mut claim = self
                .claims
                .lookup::<_, NativeClaim>(&expected.key)?
                .context("captured original owner disappeared")?;
            ensure!(expected.matches(&claim), "captured original owner changed");
            match (claim.executor, claim.state & 15) {
                (NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED) => {
                    let mut receipt = basis_receipt(basis, state, "CAPTURE_SELECTED");
                    receipt.outcome = Some("AlreadyCommitted");
                    receipt.boottime_ns = Some(clock_ns(libc::CLOCK_BOOTTIME)?);
                    state.recording.captured(receipt);
                    Ok(Some(CaptureCommit::AlreadyCommitted))
                }
                (NATIVE_EXECUTOR_PENDING, NATIVE_PHASE_PENDING) => {
                    claim.executor = NATIVE_EXECUTOR_CAPTURE;
                    claim.state = (claim.state & !15) | NATIVE_PHASE_CAPTURE_COMMITTED;
                    self.claims.insert(&expected.key, &claim, 2)?;
                    let mut receipt = basis_receipt(basis, state, "CAPTURE_SELECTED");
                    receipt.outcome = Some("CaptureCommitted");
                    receipt.boottime_ns = Some(clock_ns(libc::CLOCK_BOOTTIME)?);
                    state.recording.captured(receipt);
                    Ok(Some(CaptureCommit::Selected(CaptureProof {
                        candidate: basis.candidate,
                        basis: *basis,
                    })))
                }
                (NATIVE_EXECUTOR_KERNEL, _) => Ok(None),
                _ => anyhow::bail!("invalid captured original selection"),
            }
        });
        match result {
            Ok(selection) => {
                writer.commit();
                selection.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "original basis changed; classify again",
                    )
                    .into()
                })
            }
            Err(error) => Err(error),
        }
    }
    pub(crate) fn new_with_capacity(
        budget: Arc<MemoryBudget>,
        capacity: u32,
    ) -> anyhow::Result<Arc<Self>> {
        ensure!(capacity != 0, "native claim capacity must be nonzero");
        let monotonic_offset_ns =
            crate::xdp::host::kernel::monotonic_namespace_offset()?.unwrap_or(0);
        let mut recording = Recording::new(&budget, 0)?;
        let owner_memory = reserve(&budget, 4 * PAGE_BYTES)?;
        let root = Root::new(&budget)?;
        recording.set_root_map_id(crate::xdp::host::sys::identity(root.map.fd.as_fd())?.1)?;
        let claims = Map::new(
            &budget,
            1,
            size_of::<NativeKey>(),
            size_of::<NativeClaim>(),
            capacity,
            0,
        )?;
        let cpus = aya::util::nr_cpus().map_err(|(_, error)| error)?.get();
        ensure!(
            cpus <= 4096,
            "native possible CPU count exceeds allocation bound"
        );
        let scratch = Map::new(&budget, 2, 4, size_of::<NativeScratch>(), cpus, 0)?;
        let grace_charge = reserve(&budget, 8 * PAGE_BYTES)?;
        let grace = Grace::new()?;
        let mut memory = vec![owner_memory, grace_charge];
        let measured = grace.memory_bytes()?;
        if measured > 8 * PAGE_BYTES {
            memory.push(reserve(&budget, measured - 8 * PAGE_BYTES)?);
        }
        let clock = sample_clock()?;
        Ok(Arc::new(Self {
            root,
            claims,
            scratch,
            grace,
            budget,
            capacity,
            monotonic_offset_ns,
            state: Mutex::new(State {
                writers: Writers::default(),
                ready: false,
                capture_ready: false,
                plan: None,
                _plan_memory: None,
                targets: Vec::new(),
                hosts: Vec::new(),
                retired_hosts: Vec::new(),
                host_preparation: None,
                scopes: HashMap::new(),
                captured: None,
                captured_inventory_dirty: false,
                clock_offset: clock.offset,
                failed_resources: Vec::new(),
                retired: Vec::new(),
                retired_memory: Vec::new(),
                recording,
                operation_context: (0, 0, NativeReason::Startup),
                current_closed_seq: 1,
                current_closed_operation: 0,
                next_hook_id: 1,
                #[cfg(test)]
                test_can_open: false,
            }),
            _memory: memory,
            import_failed: AtomicBool::new(false),
            import_close_pending: AtomicBool::new(false),
            #[cfg(test)]
            test_closed: false,
            #[cfg(test)]
            write_attempts: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            test_grace: std::sync::atomic::AtomicU8::new(0),
            #[cfg(test)]
            test_grace_observed_epoch: AtomicU64::new(0),
        }))
    }

    pub(crate) fn monotonic_ns(&self) -> anyhow::Result<u64> {
        kernel_monotonic_ns(clock_ns(libc::CLOCK_MONOTONIC)?, self.monotonic_offset_ns)
    }

    #[cfg(test)]
    pub(crate) fn closed_for_test(budget: Arc<MemoryBudget>) -> anyhow::Result<Arc<Self>> {
        fn unused_map() -> io::Result<Map> {
            Ok(Map {
                fd: std::fs::File::open("/dev/null")?.into(),
                _memory: Vec::new(),
            })
        }
        let memory = reserve(&budget, 4 * PAGE_BYTES)?;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        ensure!(page > 0, "test root page size unavailable");
        let bytes = page as usize;
        let root_memory = reserve(&budget, bytes)?;
        let map = unused_map()?;
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        let root = Root {
            map,
            mapping: NonNull::new(pointer.cast()).context("null test root mapping")?,
            bytes,
            _memory: root_memory,
        };
        root.epoch().store(2, Ordering::SeqCst);
        Ok(Arc::new(Self {
            root,
            claims: unused_map()?,
            scratch: unused_map()?,
            grace: Grace::closed_for_test()?,
            state: Mutex::new(State {
                writers: Writers {
                    count: 0,
                    failed: true,
                    terminal: true,
                },
                ready: false,
                capture_ready: false,
                plan: None,
                _plan_memory: None,
                targets: Vec::new(),
                hosts: Vec::new(),
                retired_hosts: Vec::new(),
                host_preparation: None,
                scopes: HashMap::new(),
                captured: None,
                captured_inventory_dirty: false,
                clock_offset: (0, 0),
                failed_resources: Vec::new(),
                retired: Vec::new(),
                retired_memory: Vec::new(),
                recording: Recording::test_new(&budget)?,
                operation_context: (0, 0, NativeReason::Startup),
                current_closed_seq: 1,
                current_closed_operation: 0,
                next_hook_id: 1,
                test_can_open: false,
            }),
            budget,
            capacity: 1,
            monotonic_offset_ns: 0,
            _memory: vec![memory],
            import_failed: AtomicBool::new(false),
            import_close_pending: AtomicBool::new(false),
            test_closed: true,
            write_attempts: std::sync::atomic::AtomicUsize::new(0),
            test_grace: std::sync::atomic::AtomicU8::new(0),
            test_grace_observed_epoch: AtomicU64::new(0),
        }))
    }

    #[cfg(test)]
    pub(crate) fn recording_for_test(budget: Arc<MemoryBudget>) -> anyhow::Result<Arc<Self>> {
        let publication = Self::closed_for_test(budget)?;
        publication.root.epoch().store(0, Ordering::SeqCst);
        publication.test_grace.store(1, Ordering::SeqCst);
        {
            let mut state = publication.state.lock();
            state.writers = Writers::default();
            state.ready = true;
            state.capture_ready = true;
            state.test_can_open = true;
        }
        Ok(publication)
    }

    #[cfg(test)]
    pub(crate) fn recording_events_for_test(&self) -> Vec<NativePublicationEventV1> {
        self.state.lock().recording.events().copied().collect()
    }

    #[cfg(test)]
    pub(crate) fn epoch_for_test(&self) -> u64 {
        self.root.epoch().load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn insert_claim_for_test(
        &self,
        key: &NativeKey,
        claim: &NativeClaim,
    ) -> io::Result<()> {
        self.claims.insert(key, claim, 0)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(self: &Arc<Self>) -> anyhow::Result<()> {
        self.state.lock().test_can_open = true;
        self.write(NativeReason::Startup)?.commit();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn write_attempts_for_test(&self) -> usize {
        self.write_attempts.load(Ordering::Relaxed)
    }

    fn reader_grace(&self) -> anyhow::Result<()> {
        #[cfg(test)]
        self.test_grace_observed_epoch
            .store(self.root.epoch().load(Ordering::SeqCst), Ordering::SeqCst);
        #[cfg(test)]
        match self.test_grace.load(Ordering::SeqCst) {
            1 => return Ok(()),
            2 => anyhow::bail!("injected native reader grace failure"),
            _ => {}
        }
        self.grace.barrier()
    }

    fn store_recorded(
        &self,
        state: &mut State,
        epoch_after: u64,
        operation_id: u64,
        writer_id: u64,
        reason: NativeReason,
        reopen: bool,
    ) -> u64 {
        let epoch_before = self.root.epoch().load(Ordering::SeqCst);
        let intent = state.recording.append(NativePublicationEventV1 {
            operation_id,
            writer_id,
            epoch_before,
            epoch_after,
            kind: if reopen {
                NATIVE_EVENT_REOPEN_INTENT
            } else {
                NATIVE_EVENT_CLOSE_INTENT
            },
            reason: reason as u32,
            ..Default::default()
        });
        let before = state.recording.time();
        if reopen
            && (self.import_failed.load(Ordering::Acquire)
                || before.is_none()
                || state.recording.recording_error)
        {
            state.writers.failed = true;
            return 0;
        }
        if reopen {
            if self
                .root
                .epoch()
                .compare_exchange(
                    epoch_before,
                    epoch_after,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_err()
            {
                state.writers.failed = true;
                state.recording.accounting_error = true;
                state.recording.append(NativePublicationEventV1 {
                    operation_id,
                    writer_id,
                    epoch_before,
                    epoch_after: self.root.epoch().load(Ordering::SeqCst),
                    kind: NATIVE_EVENT_TERMINAL_STATE,
                    reason: NativeReason::MapReadFailure as u32,
                    outcome: NATIVE_OUTCOME_FAILED,
                    ..Default::default()
                });
                return 0;
            }
        } else {
            self.root.epoch().store(epoch_after, Ordering::SeqCst);
        }
        let after = state.recording.time();
        let valid = before.is_some() && after.is_some();
        let seq = state.recording.append(NativePublicationEventV1 {
            operation_id,
            writer_id,
            epoch_before,
            epoch_after,
            boottime_before_ns: before.unwrap_or(0),
            boottime_after_ns: after.unwrap_or(0),
            related_seq: intent,
            kind: if reopen {
                NATIVE_EVENT_REOPEN_STORED
            } else {
                NATIVE_EVENT_CLOSE_STORED
            },
            reason: reason as u32,
            outcome: if valid {
                NATIVE_OUTCOME_COMMITTED
            } else {
                NATIVE_OUTCOME_FAILED
            },
            flags: if valid {
                NATIVE_EVENT_FLAG_TIMESTAMP_VALID
            } else {
                0
            },
            ..Default::default()
        });
        if !valid {
            state.writers.failed = true;
        }
        seq
    }

    fn seal_counters(&self, state: &mut State, final_epoch: bool) -> anyhow::Result<()> {
        let current = (!final_epoch).then(|| self.root.epoch().load(Ordering::SeqCst) & !1);
        let State {
            targets, recording, ..
        } = state;
        for target in targets {
            if let Err(error) = target.counters.seal(current, target.hook_ids, recording) {
                recording.accounting_error = true;
                return Err(error);
            }
        }
        Ok(())
    }

    fn drain_recorded(&self, state: &mut State, reason: NativeReason) -> anyhow::Result<()> {
        let operation_id = state.recording.operation();
        let epoch = self.root.epoch().load(Ordering::SeqCst);
        let result = self.reader_grace();
        if result.is_err() {
            state.writers.failed = true;
        }
        let time = if result.is_ok() {
            state.recording.time()
        } else {
            None
        };
        state.recording.append(NativePublicationEventV1 {
            operation_id,
            epoch_before: epoch,
            epoch_after: epoch,
            related_seq: state.current_closed_seq,
            boottime_after_ns: time.unwrap_or(0),
            kind: if result.is_ok() {
                NATIVE_EVENT_CLOSE_DRAINED
            } else {
                NATIVE_EVENT_TERMINAL_STATE
            },
            reason: reason as u32,
            outcome: if result.is_ok() && time.is_some() {
                NATIVE_OUTCOME_COMMITTED
            } else {
                NATIVE_OUTCOME_FAILED
            },
            flags: if time.is_some() {
                NATIVE_EVENT_FLAG_TIMESTAMP_VALID
            } else {
                0
            },
            ..Default::default()
        });
        result
    }

    fn close_recorded(
        &self,
        state: &mut State,
        closed: u64,
        operation_id: u64,
        writer_id: u64,
        reason: NativeReason,
        terminal: bool,
    ) -> anyhow::Result<()> {
        let previous = self.root.epoch().load(Ordering::SeqCst);
        let mut preparation = Ok(());
        if previous != closed {
            for target in &mut state.targets {
                if let Err(error) = target.counters.prepare(closed, operation_id, 0) {
                    state.recording.accounting_error = true;
                    state.writers.failed = true;
                    preparation = Err(error);
                    break;
                }
            }
            let seq = self.store_recorded(state, closed, operation_id, writer_id, reason, false);
            state.current_closed_seq = seq;
            state.current_closed_operation = operation_id;
            for target in &mut state.targets {
                let generation = &mut target.counters.generations[((closed >> 1) & 255) as usize];
                if generation.live && generation.epoch == closed {
                    generation.related_seq = seq;
                }
            }
        }
        let grace = self.reader_grace();
        if grace.is_ok() {
            let time = state.recording.time();
            state.recording.append(NativePublicationEventV1 {
                operation_id,
                writer_id,
                epoch_before: previous,
                epoch_after: closed,
                related_seq: state.current_closed_seq,
                boottime_after_ns: time.unwrap_or(0),
                kind: NATIVE_EVENT_CLOSE_DRAINED,
                reason: reason as u32,
                outcome: if time.is_some() {
                    NATIVE_OUTCOME_COMMITTED
                } else {
                    NATIVE_OUTCOME_FAILED
                },
                flags: if time.is_some() {
                    NATIVE_EVENT_FLAG_TIMESTAMP_VALID
                } else {
                    0
                },
                ..Default::default()
            });
            if let Err(error) = self.seal_counters(state, false) {
                preparation = Err(error);
            }
        } else {
            state.writers.failed = true;
        }
        if terminal {
            state.recording.append(NativePublicationEventV1 {
                operation_id,
                writer_id,
                epoch_before: previous,
                epoch_after: closed,
                related_seq: state.current_closed_seq,
                kind: NATIVE_EVENT_TERMINAL_STATE,
                reason: reason as u32,
                outcome: if grace.is_ok() && preparation.is_ok() {
                    NATIVE_OUTCOME_COMMITTED
                } else {
                    NATIVE_OUTCOME_FAILED
                },
                ..Default::default()
            });
        }
        grace?;
        preparation
    }

    fn recording_snapshot(&self, state: &State, hooks_joined: bool) -> Snapshot {
        Snapshot {
            epoch: self.root.epoch().load(Ordering::SeqCst),
            flags: self.root.flags().load(Ordering::SeqCst),
            ready: state.ready,
            capture_ready: state.capture_ready,
            failed: state.writers.failed,
            terminal: state.writers.terminal,
            hooks_joined,
            all_counters_sealed: state.targets.iter().all(|target| {
                target
                    .counters
                    .generations
                    .iter()
                    .all(|generation| !generation.live)
            }),
        }
    }

    pub(crate) fn initialize_export(
        &self,
        data_dir: &std::path::Path,
    ) -> anyhow::Result<std::path::PathBuf> {
        let mut state = self.state.lock();
        let snapshot = self.recording_snapshot(&state, false);
        state.recording.initialize_export(data_dir, snapshot)
    }

    #[cfg(test)]
    pub(crate) fn initial_checkpoint(&self) -> Option<(std::path::PathBuf, [u8; 32], u64)> {
        self.state.lock().recording.initial_checkpoint()
    }

    pub(crate) fn finalize_recording(&self, hooks_joined: bool) -> anyhow::Result<()> {
        let mut state = self.state.lock();
        if state.recording.completed {
            return Ok(());
        }
        if !state.writers.terminal
            || state.writers.count != 0
            || self.root.epoch().load(Ordering::SeqCst) & 1 != 0
        {
            state.writers.failed = true;
            anyhow::bail!("native recording finalization requires terminal owners");
        }
        let eligible = !state.writers.failed;
        let grace = self.drain_recorded(&mut state, NativeReason::Shutdown);
        if !hooks_joined {
            state.writers.failed = true;
            return match grace {
                Ok(()) => Err(anyhow::anyhow!("native recording hooks remain unjoined")),
                Err(error) => Err(error.context("native recording hooks remain unjoined")),
            };
        }
        grace?;
        ensure!(eligible, "native recording finalization remains failed");
        if let Err(error) = self.seal_counters(&mut state, true) {
            state.writers.failed = true;
            return Err(error);
        }
        state.recording.hooks_joined = true;
        let time = state.recording.time();
        let epoch = self.root.epoch().load(Ordering::SeqCst);
        state.recording.append(NativePublicationEventV1 {
            epoch_before: epoch,
            epoch_after: epoch,
            kind: NATIVE_EVENT_COLLECTION_END,
            reason: NativeReason::Shutdown as u32,
            outcome: if time.is_some() {
                NATIVE_OUTCOME_COMMITTED
            } else {
                NATIVE_OUTCOME_FAILED
            },
            boottime_after_ns: time.unwrap_or(0),
            flags: if time.is_some() {
                NATIVE_EVENT_FLAG_TIMESTAMP_VALID
            } else {
                0
            },
            ..Default::default()
        });
        state.recording.completed = true;
        ensure!(
            !state.recording.clock_error
                && !state.recording.accounting_error
                && !state.recording.recording_error,
            "native recording finalization incomplete"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_grace_failure_for_test(&self, fail: bool) {
        self.test_grace
            .store(if fail { 2 } else { 1 }, Ordering::SeqCst);
    }

    pub(crate) fn export_recording(
        &self,
        final_export: bool,
        hooks_joined: bool,
    ) -> NativeExportResult {
        let mut state = self.state.lock();
        let snapshot =
            self.recording_snapshot(&state, hooks_joined && state.recording.hooks_joined);
        let final_export = final_export && state.recording.completed;
        state.recording.export(final_export, snapshot)
    }

    pub(crate) fn admit_topology(
        &self,
        physical: &[u32],
        logical: &[u32],
        mark: u32,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Topology> {
        self.admit_topology_with(|state| {
            let mut topology = Topology::admit_after_xdp_attach(physical, logical, mark)?;
            let updates = topology.enable_native_xdp_updates(budget)?;
            for entry in &state.targets {
                entry.target.bind_native_xdp_updates(updates.clone())?;
            }
            if topology.check_changed()? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Native topology changed during final binding",
                ));
            }
            Ok(topology)
        })
    }

    fn admit_topology_with<T>(&self, admit: impl FnOnce(&State) -> io::Result<T>) -> io::Result<T> {
        // DNS publication is already installed; keep it outside the subscription/binding gap.
        let mut state = self.state.lock();
        if state.writers.failed || state.writers.terminal {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Native publication is permanently closed",
            ));
        }
        let result = admit(&state);
        if let Err(error) = &result {
            state.writers.failed = true;
            state.ready = false;
            state.capture_ready = false;
            let epoch = self.root.epoch().load(Ordering::SeqCst);
            let operation = state.recording.operation();
            if let Err(close) = self.close_recorded(
                &mut state,
                epoch.saturating_add(epoch & 1) & !1,
                operation,
                0,
                NativeReason::Startup,
                true,
            ) {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{error}; Native startup close also failed: {close:#}"),
                ));
            }
        }
        result
    }

    pub(crate) fn write(self: &Arc<Self>, reason: NativeReason) -> anyhow::Result<NativeWrite> {
        #[cfg(test)]
        self.write_attempts.fetch_add(1, Ordering::Relaxed);
        let mut state = self.state.lock();
        self.write_locked(&mut state, reason)
    }

    fn write_locked(
        self: &Arc<Self>,
        state: &mut State,
        reason: NativeReason,
    ) -> anyhow::Result<NativeWrite> {
        ensure!(
            !state.recording.recording_error
                && !state.recording.clock_error
                && !state.recording.accounting_error,
            "native recording is incomplete"
        );
        ensure!(
            !state.writers.failed
                && !state.writers.terminal
                && !self.import_failed.load(Ordering::Acquire),
            "native publication is permanently closed"
        );
        let writer_id = state.recording.writer();
        let operation_id = state.recording.operation();
        state.writers.begin()?;
        state.recording.append(NativePublicationEventV1 {
            writer_id,
            operation_id,
            reason: reason as u32,
            kind: NATIVE_EVENT_WRITER_BEGIN,
            ..Default::default()
        });
        let epoch = self.root.epoch().load(Ordering::SeqCst);
        let closed = next_closed(epoch);
        let result = self.close_recorded(
            state,
            closed.unwrap_or(u64::MAX - 1),
            operation_id,
            writer_id,
            if closed.is_none() {
                NativeReason::EpochExhaustion
            } else {
                reason
            },
            false,
        );
        if closed.is_none()
            || result.is_err()
            || state.recording.recording_error
            || state.recording.clock_error
            || state.recording.accounting_error
        {
            state.writers.failed = true;
            state.writers.count -= 1;
            state.recording.append(NativePublicationEventV1 {
                operation_id,
                writer_id,
                reason: reason as u32,
                kind: NATIVE_EVENT_WRITER_OUTCOME,
                outcome: NATIVE_OUTCOME_FAILED,
                ..Default::default()
            });
            result?;
            ensure!(closed.is_some(), "native epoch exhausted");
            anyhow::bail!("native recording frontier incomplete");
        }
        Ok(NativeWrite {
            publication: self.clone(),
            epoch: closed.unwrap_or(u64::MAX - 1),
            committed: false,
            writer_id,
            operation_id,
            reason,
            host_preparation: None,
        })
    }

    fn change<T>(
        self: &Arc<Self>,
        writer: &NativeWrite,
        reason: NativeReason,
        apply: impl FnOnce(&mut State) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut state = self.state.lock();
        ensure!(
            Arc::ptr_eq(self, &writer.publication)
                && state
                    .recording
                    .is_live_writer(writer.writer_id, writer.operation_id),
            "native change requires its initiating live writer"
        );
        ensure!(
            state.writers.count != 0 && !state.writers.failed && !state.writers.terminal,
            "native publication is permanently closed"
        );
        let operation_id = state.recording.operation();
        let writer_id = writer.writer_id;
        let seq = state.recording.append(NativePublicationEventV1 {
            operation_id,
            writer_id,
            reason: reason as u32,
            kind: NATIVE_EVENT_WRITER_BEGIN,
            ..Default::default()
        });
        ensure!(seq != 0, "native participant was not recorded");
        let previous_context = state.operation_context;
        state.operation_context = (operation_id, writer_id, reason);
        let result = apply(&mut state);
        state.operation_context = previous_context;
        if result.is_err() {
            state.writers.failed = true;
        }
        state.recording.append(NativePublicationEventV1 {
            operation_id,
            writer_id,
            reason: reason as u32,
            kind: NATIVE_EVENT_WRITER_OUTCOME,
            outcome: if result.is_ok() {
                NATIVE_OUTCOME_COMMITTED
            } else {
                NATIVE_OUTCOME_FAILED
            },
            ..Default::default()
        });
        result
    }

    pub(crate) fn publish_plan(
        self: &Arc<Self>,
        plan: &RoutingPushPlan,
        writer: &NativeWrite,
    ) -> anyhow::Result<()> {
        self.change(writer, NativeReason::Policy, |state| {
            let mut prepared = self.take_host_preparation(state, plan, writer)?;
            let charge = match prepared
                .as_mut()
                .and_then(|prepared| prepared.plan_memory.take())
            {
                Some(memory) => memory,
                None => reserve(&self.budget, plan_bytes(plan)?)?,
            };
            self.publish_candidates(state, plan, prepared)?;
            state.plan = Some(plan.clone());
            state._plan_memory = Some(charge);
            Ok(())
        })
    }

    pub(crate) fn register(
        self: &Arc<Self>,
        target: Arc<NativeTarget>,
        scope: ScopeId,
    ) -> anyhow::Result<()> {
        let writer = self.write(NativeReason::Startup)?;
        let result = self.change(&writer, NativeReason::Startup, |state| {
            ensure!(
                state.hosts.is_empty(),
                "combined Host and physical Native requires actual Host reverse exclusion"
            );
            ensure!(
                scope != ScopeId::HOST,
                "native target requires its actual packet scope"
            );
            ensure!(
                !state
                    .targets
                    .iter()
                    .any(|entry| Arc::ptr_eq(&entry.target, &target)),
                "native target already registered"
            );
            // Target/HashMap growth and program ownership are charged before staging.
            let memory = reserve(&self.budget, 4 * PAGE_BYTES)?;
            let next_hook_id = state
                .next_hook_id
                .checked_add(2)
                .context("native hook identities exhausted");
            if next_hook_id.is_err() {
                state.recording.recording_error = true;
            }
            let next_hook_id = next_hook_id?;
            let hook_ids = [state.next_hook_id, state.next_hook_id + 1];
            let (namespace_cookie, ifindex) = target.recording_identity()?;
            let attachment_generation = target.capture().authority.attachment_generation;
            let mut counters = ClosedCounters::new(&self.budget)?;
            let counter_map_id = crate::xdp::host::sys::identity(counters.map.fd.as_fd())?.1;
            counters.prepare(
                self.root.epoch().load(Ordering::SeqCst),
                state.current_closed_operation,
                state.current_closed_seq,
            )?;
            for (kind, hook_id) in hook_ids.into_iter().enumerate() {
                state.recording.register_hook(HookIdentity {
                    hook_id,
                    target_serial: hook_ids[0].div_ceil(2),
                    kind: kind as u32,
                    scope: scope.as_u64(),
                    namespace_cookie,
                    ifindex,
                    attachment_generation,
                    counter_map_id,
                    program_id: 0,
                })?;
            }
            state.next_hook_id = next_hook_id;
            state.targets.try_reserve_exact(1)?;
            state.targets.push(Target {
                target,
                scope,
                active: None,
                _memory: memory,
                counters,
                hook_ids,
                attachment_generation,
            });
            if let Some(plan) = state.plan.take() {
                let result = self.publish_candidates(state, &plan, None);
                state.plan = Some(plan);
                result?;
            }
            Ok(())
        });
        if result.is_ok() {
            writer.commit();
        }
        result
    }

    pub(crate) fn scope_is_current(
        &self,
        scope: ScopeId,
        revision: u64,
        generation: u64,
        fingerprint: [u8; 32],
        facts: impl Iterator<Item = (IpAddr, DomainRouting, Option<tokio::time::Instant>)>,
    ) -> bool {
        let state = self.state.lock();
        let now = tokio::time::Instant::now();
        !(state.targets.iter().any(|target| target.scope == scope)
            || (scope == ScopeId::HOST && !state.hosts.is_empty()))
            || state.scopes.get(&scope).is_some_and(|installed| {
                installed.matches(revision, generation, fingerprint, now, facts)
            })
    }

    pub(crate) fn renewal_deadline(&self) -> anyhow::Result<Option<tokio::time::Instant>> {
        let state = self.state.lock();
        let physical = state
            .targets
            .iter()
            .filter(|target| target.active.is_some())
            .filter_map(|target| state.scopes.get(&target.scope));
        let host = state
            .hosts
            .iter()
            .any(|target| target.active.is_some())
            .then(|| state.scopes.get(&ScopeId::HOST))
            .flatten();
        let deadline = physical
            .chain(host)
            .flat_map(|scope| scope.facts.iter().map(|entry| entry.2))
            .filter(|deadline| *deadline != u64::MAX)
            .min();
        let Some(deadline) = deadline else {
            return Ok(None);
        };
        // Tokio first: conversion schedules at or before the installed BOOTTIME horizon.
        let now = tokio::time::Instant::now();
        let boot = clock_ns(libc::CLOCK_BOOTTIME)?;
        now.checked_add(std::time::Duration::from_nanos(
            deadline.saturating_sub(boot),
        ))
        .map(Some)
        .context("native renewal deadline overflow")
    }

    pub(crate) fn update_scope(
        self: &Arc<Self>,
        scope: ScopeId,
        revision: u64,
        generation: u64,
        fingerprint: [u8; 32],
        facts: &[(IpAddr, DomainRouting, Option<tokio::time::Instant>)],
        writer: &NativeWrite,
    ) -> anyhow::Result<()> {
        // HOST uses its actual DNS snapshot, just like each physical packet scope.
        self.change(writer, NativeReason::ScopedDns, |state| {
            ensure!(
                facts.len() <= super::maps::DOMAIN_MAP_CAPACITY as usize,
                "native scope fact capacity exceeded"
            );
            let sample = sample_clock()?;
            let low = state.clock_offset.0.max(sample.offset.0);
            let high = state.clock_offset.1.min(sample.offset.1);
            ensure!(
                low <= high,
                "native BOOTTIME/MONOTONIC relationship changed"
            );
            state.clock_offset = (low, high);
            if let Some(previous) = state.scopes.get(&scope) {
                ensure!(
                    generation >= previous.generation && revision >= previous.revision,
                    "native scope snapshot regressed"
                );
                if previous.matches(
                    revision,
                    generation,
                    fingerprint,
                    sample.now,
                    facts.iter().copied(),
                ) {
                    return Ok(());
                }
            }
            let memory = reserve(
                &self.budget,
                facts
                    .len()
                    .checked_mul(
                        size_of::<([u32; 4], DomainRouting, u64, Option<tokio::time::Instant>)>()
                            * 3,
                    )
                    .and_then(|n| n.checked_add(4 * PAGE_BYTES))
                    .context("native snapshot charge overflow")?,
            )?;
            let mut entries = Vec::with_capacity(facts.len());
            for (ip, bitmap, expiry) in facts {
                let mut deadline = match expiry {
                    None => u64::MAX,
                    Some(expiry) => {
                        if *expiry <= sample.now {
                            continue;
                        }
                        let remaining = *expiry - sample.now;
                        sample
                            .boot
                            .checked_add(u64::try_from(remaining.as_nanos())?)
                            .context("native DNS deadline overflow")?
                    }
                };
                let key = super::maps::ip_addr_to_lpm_key(*ip).data;
                if let Some(previous) = state.scopes.get(&scope).and_then(|scope| {
                    scope
                        .facts
                        .binary_search_by_key(&key, |entry| entry.0)
                        .ok()
                        .map(|index| &scope.facts[index])
                }) && previous.3 == *expiry
                {
                    deadline = deadline.min(previous.2);
                }
                entries.push((key, *bitmap, deadline, *expiry));
            }
            entries.sort_unstable_by_key(|entry| entry.0);
            ensure!(
                entries.windows(2).all(|pair| pair[0].0 != pair[1].0),
                "duplicate native domain key"
            );
            state.scopes.insert(
                scope,
                Scope {
                    revision,
                    generation,
                    fingerprint,
                    facts: entries,
                    _memory: memory,
                },
            );
            if !state.targets.iter().any(|target| target.scope == scope)
                && !(scope == ScopeId::HOST && !state.hosts.is_empty())
            {
                return Ok(());
            }
            if let Some(plan) = state.plan.take() {
                let result = self.publish_candidates(state, &plan, None);
                state.plan = Some(plan);
                result?;
            }
            Ok(())
        })
    }

    fn publish_candidates(
        &self,
        state: &mut State,
        plan: &RoutingPushPlan,
        mut prepared: Option<HostPlanReservations>,
    ) -> anyhow::Result<()> {
        if state.targets.is_empty() && state.hosts.is_empty() {
            return Ok(());
        }
        if !state.targets.is_empty() {
            admit_physical_effects(plan)?;
        }
        state.captured_inventory_dirty = state
            .captured
            .as_ref()
            .is_some_and(|binding| binding.programs.is_some());
        let captured_binding = state.captured.as_ref().and_then(|binding| {
            binding
                .programs
                .as_ref()
                .map(|programs| (binding, programs))
        });
        let captured_config = captured_binding.map(|(binding, programs)| CapturedProgramConfig {
            root: binding.cell.root_fd(),
            operation: binding.cell.operation_fd(),
            return_attachment: programs.return_attachment(),
            tap_ifindex: programs.tap_ifindex(),
            targets: programs.targets(),
            pin_root: programs.pin_root(),
        });
        let compiler_memory = compiler_bytes(plan, captured_config.is_some())?;
        let redirect_limit = self
            .capacity
            .checked_sub(4096 + 64 + 4096)
            .unwrap_or(self.capacity);
        ensure!(
            (1..=(1 << 28) - 1).contains(&redirect_limit),
            "Native redirect limit exceeds counted ABI"
        );
        let proof_bytes = plan
            .rules
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(size_of::<u32>()))
            .context("native reply proof charge overflow")?;
        let _proof_memory = match prepared.as_mut().and_then(|prepared| prepared.proof.take()) {
            Some(memory) => memory,
            None => reserve(&self.budget, proof_bytes)?,
        };
        let reply_block_rules = reply_block_rules(plan);
        let mut candidates = Vec::with_capacity(state.targets.len());
        state.failed_resources.try_reserve(state.targets.len())?;
        state.retired.try_reserve(state.targets.len())?;
        let facts = Arc::new(
            match prepared.as_mut().and_then(|prepared| prepared.facts.take()) {
                Some(reservations) => {
                    Facts::new_reserved(&self.budget, &plan.facts, Some(reservations))?
                }
                None => Facts::new(&self.budget, &plan.facts)?,
            },
        );
        let staged = (|| -> anyhow::Result<()> {
            for target in &state.targets {
                let scope = state
                    .scopes
                    .get(&target.scope)
                    .filter(|scope| scope.fingerprint == plan.policy_fingerprint);
                let entries = scope.map_or(&[][..], |scope| scope.facts.as_slice());
                let domain = Map::new(
                    &self.budget,
                    1,
                    16,
                    size_of::<DomainRouting>(),
                    u32::try_from(entries.len().max(1))?,
                    0,
                )?;
                let mut deadline = u64::MAX;
                for (key, bitmap, expires, _) in entries {
                    domain.insert(key, bitmap, 0)?;
                    deadline = deadline.min(*expires);
                }
                domain.freeze()?;
                let preparation_memory = target.target.preparation_memory_bytes()?;
                let temporary_memory = compiler_memory
                    .checked_add(preparation_memory)
                    .context("native preparation charge overflow")?;
                let temporary = reserve(&self.budget, temporary_memory)?;
                let bytecode = emit_routing_program(plan, facts.fds(domain.fd()))?;
                let programs = match target.target.prepare(&NativeProgramConfig {
                    bytecode: &bytecode.insns,
                    root: self.root.map.fd(),
                    claims: self.claims.fd(),
                    scratch: self.scratch.fd(),
                    closed_counters: target.counters.map.fd(),
                    hook_ids: target.hook_ids,
                    epoch: self.root.epoch().load(Ordering::SeqCst),
                    scope: target.scope.as_u64(),
                    expires_boottime_ns: deadline,
                    reply_block_rules: &reply_block_rules,
                    preparation_memory_bytes: preparation_memory,
                    redirect_limit,
                    captured: captured_config.as_ref(),
                }) {
                    Ok(programs) => programs,
                    Err(error) => {
                        state.failed_resources.push(CandidateResources {
                            facts: facts.clone(),
                            domain,
                            memory: temporary,
                        });
                        return Err(error.into());
                    }
                };
                let memory = match programs
                    .memory_bytes()
                    .map_err(anyhow::Error::from)
                    .and_then(|bytes| reserve(&self.budget, bytes))
                {
                    Ok(memory) => memory,
                    Err(error) => {
                        candidates.push(Candidate {
                            programs,
                            resources: CandidateResources {
                                facts: facts.clone(),
                                domain,
                                memory: temporary,
                            },
                        });
                        return Err(error);
                    }
                };
                drop(bytecode);
                drop(temporary);
                candidates.push(Candidate {
                    programs,
                    resources: CandidateResources {
                        facts: facts.clone(),
                        domain,
                        memory,
                    },
                });
            }
            Ok(())
        })();
        if let Err(error) = staged {
            state.retired.extend(candidates);
            if let Some(facts) = Arc::into_inner(facts) {
                for map in facts.maps {
                    map.retire(&mut state.retired_memory);
                }
            }
            return Err(error);
        }
        let host_candidates = match self.prepare_host_candidates(state, plan, &facts, prepared) {
            Ok(candidates) => candidates,
            Err(error) => {
                state.retired.extend(candidates);
                if let Some(facts) = Arc::into_inner(facts) {
                    for map in facts.maps {
                        map.retire(&mut state.retired_memory);
                    }
                }
                return Err(error);
            }
        };
        // No stable dispatch changes until every candidate, map and program exists.
        let mut candidates = candidates.into_iter();
        for target in &mut state.targets {
            let candidate = candidates
                .next()
                .expect("one prepared candidate per target");
            let old = target
                .active
                .as_ref()
                .map(|candidate| {
                    [
                        candidate.programs.program_id(),
                        candidate.programs.tc_program_id(),
                    ]
                })
                .unwrap_or([0, 0]);
            let new = [
                candidate.programs.program_id(),
                candidate.programs.tc_program_id(),
            ];
            for hook in 0..2 {
                let (operation_id, writer_id, reason) = state.operation_context;
                if let Err(error) = state.recording.program_replacement(
                    target.hook_ids[hook],
                    old[hook],
                    new[hook],
                    NATIVE_OUTCOME_PENDING,
                    reason,
                    operation_id,
                    writer_id,
                ) {
                    state.retired.push(candidate);
                    state.retired.extend(candidates);
                    return Err(error);
                }
            }
            if let Err(error) = candidate.programs.publish(&target.target) {
                // A multi-hook dispatch update may have published a prefix before failing.
                state.retired.push(candidate);
                state.retired.extend(candidates);
                state.recording.recording_error = true;
                return Err(error.into());
            }
            let mut identity_result = Ok(());
            for hook in 0..2 {
                let (operation_id, writer_id, reason) = state.operation_context;
                if let Err(error) = state.recording.program_replacement(
                    target.hook_ids[hook],
                    old[hook],
                    new[hook],
                    NATIVE_OUTCOME_COMMITTED,
                    reason,
                    operation_id,
                    writer_id,
                ) {
                    identity_result = Err(error);
                    break;
                }
            }
            let generation = target.attachment_generation.checked_add(1);
            if let Some(generation) = generation {
                target.attachment_generation = generation;
            } else {
                state.recording.recording_error = true;
                identity_result = Err(anyhow::anyhow!("native attachment generation exhausted"));
            }
            if let Some(previous) = target.active.replace(candidate) {
                state.retired.push(previous);
            }
            if let Err(error) = identity_result {
                state.retired.extend(candidates);
                return Err(error);
            }
        }
        self.publish_host_candidates(state, host_candidates)?;
        let reason = state.operation_context.2;
        // nft route wrappers and selector readers must finish before any new open epoch.
        self.drain_recorded(state, reason)?;
        self.seal_counters(state, false)?;
        for target in &state.targets {
            target.target.finish_publication()?;
        }
        state.finish_retirement();
        Ok(())
    }

    pub(crate) fn terminal(&self) -> bool {
        self.state.lock().writers.terminal
    }

    pub(crate) fn set_flags(self: &Arc<Self>, flags: u32) -> anyhow::Result<()> {
        let mut state = self.state.lock();
        if state.writers.terminal {
            ensure!(
                !state.recording.completed || self.root.flags().load(Ordering::SeqCst) == flags,
                "native recording already finalized"
            );
            if state.recording.completed {
                return Ok(());
            }
            let operation_id = state.recording.operation();
            let writer_id = state.recording.writer();
            state.recording.append(NativePublicationEventV1 {
                operation_id,
                writer_id,
                kind: NATIVE_EVENT_WRITER_BEGIN,
                reason: NativeReason::Flags as u32,
                ..Default::default()
            });
            self.root.flags().store(flags, Ordering::SeqCst);
            state.recording.append(NativePublicationEventV1 {
                operation_id,
                writer_id,
                kind: NATIVE_EVENT_WRITER_OUTCOME,
                reason: NativeReason::Flags as u32,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Default::default()
            });
            return Ok(());
        }
        let writer = self.write_locked(&mut state, NativeReason::Flags)?;
        self.root.flags().store(flags, Ordering::SeqCst);
        drop(state);
        writer.commit();
        Ok(())
    }
    pub(crate) fn set_ready(self: &Arc<Self>, ready: bool) -> anyhow::Result<()> {
        let mut state = self.state.lock();
        if state.writers.terminal {
            ensure!(!ready, "native terminal publication cannot become ready");
            state.ready = false;
            return Ok(());
        }
        let writer = self.write_locked(&mut state, NativeReason::Ready)?;
        state.ready = ready;
        drop(state);
        writer.commit();
        Ok(())
    }
    pub(crate) fn set_capture_ready(self: &Arc<Self>, ready: bool) -> anyhow::Result<()> {
        let writer = self.write(NativeReason::CaptureReady)?;
        let result = self.change(&writer, NativeReason::CaptureReady, |state| {
            state.capture_ready = ready;
            Ok(())
        });
        if result.is_ok() {
            writer.commit();
        }
        result
    }
    pub(crate) fn quiesce(self: &Arc<Self>, reason: NativeReason) -> anyhow::Result<()> {
        let mut state = self.state.lock();
        if state.recording.completed {
            return Ok(());
        }
        state.writers.terminal = true;
        let epoch = self.root.epoch().load(Ordering::SeqCst);
        let operation = state.recording.operation();
        self.close_recorded(
            &mut state,
            epoch.saturating_add(epoch & 1) & !1,
            operation,
            0,
            reason,
            true,
        )
    }

    fn read_result<T>(&self, result: io::Result<T>) -> anyhow::Result<T> {
        result.map_err(|error| {
            let mut state = self.state.lock();
            state.writers.failed = true;
            let epoch = self.root.epoch().load(Ordering::SeqCst);
            let operation = state.recording.operation();
            match self.close_recorded(
                &mut state,
                epoch.saturating_add(epoch & 1) & !1,
                operation,
                0,
                NativeReason::MapReadFailure,
                true,
            ) {
                Ok(()) => anyhow::Error::new(error),
                Err(grace) => {
                    anyhow::anyhow!("native map syscall: {error}; closing reader grace: {grace:#}")
                }
            }
        })
    }

    /// Exact BPF-created ownership. Looking up a packet's import never changes its epoch.
    pub(crate) fn claim(&self, key: &NativeKey) -> anyhow::Result<Option<NativeClaim>> {
        self.read_result(self.lookup_claim(key))
    }

    pub(crate) fn import_claim(&self, key: &NativeKey) -> io::Result<Option<NativeClaim>> {
        self.import_lookup_result(self.lookup_claim(key))
    }

    fn import_lookup_result<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            self.import_failed.store(true, Ordering::Release);
            self.import_close_pending.store(true, Ordering::Release);
            let root = self.root.epoch();
            let mut epoch = root.load(Ordering::SeqCst);
            loop {
                let closed = next_closed(epoch).unwrap_or(u64::MAX - 1);
                match root.compare_exchange_weak(epoch, closed, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => break,
                    Err(current) => epoch = current,
                }
            }
        }
        result
    }

    pub(crate) fn finish_import_turn(&self) -> anyhow::Result<()> {
        if self.import_close_pending.swap(false, Ordering::AcqRel) {
            let mut state = self.state.lock();
            state.writers.failed = true;
            state.ready = false;
            state.capture_ready = false;
            // Emergency closure in RX precedes its owner journal/grace; completeness is lost.
            state.recording.accounting_error = true;
            let epoch = self.root.epoch().load(Ordering::SeqCst);
            let operation = state.recording.operation();
            self.close_recorded(
                &mut state,
                next_closed(epoch).unwrap_or(u64::MAX - 1),
                operation,
                0,
                NativeReason::MapReadFailure,
                true,
            )?;
        }
        Ok(())
    }

    fn lookup_claim(&self, key: &NativeKey) -> io::Result<Option<NativeClaim>> {
        if !key.is_valid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Native key projection",
            ));
        }
        let claim = self.claims.lookup::<_, NativeClaim>(key)?;
        if claim.as_ref().is_some_and(|claim| !claim.is_valid(key)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Native claim identity",
            ));
        }
        Ok(claim)
    }

    /// Advisory only: insertions behind the cursor and endpoint retirement after
    /// visitation may wait for the next maintenance turn. This never authorizes deletion.
    pub(crate) fn maintenance_needed(
        &self,
        candidate: impl FnMut(&NativeKey, &NativeClaim) -> bool,
    ) -> anyhow::Result<bool> {
        self.read_result(scan_claim_candidates(
            self.capacity,
            || self.root.epoch().load(Ordering::SeqCst),
            |previous| {
                let mut next = NativeKey::default();
                match element(
                    4,
                    self.claims.fd(),
                    previous.map_or(0, |key| key as *const NativeKey as u64),
                    &mut next as *mut NativeKey as u64,
                    0,
                ) {
                    Ok(_) => Ok(Some(next)),
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
                    Err(error) => Err(error),
                }
            },
            |key| self.lookup_claim(key),
            candidate,
        ))
    }

    pub(crate) fn query_claim(
        &self,
        key: &NativeKey,
        expected: &NativeClaim,
        query: impl FnOnce() -> io::Result<bool>,
    ) -> anyhow::Result<Option<bool>> {
        if !expected.is_transit(key) {
            return self.read_result(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Native query identity",
            )));
        }
        let state = self.state.lock();
        let epoch = self.root.epoch().load(Ordering::SeqCst);
        if state.writers.count == 0
            || state.writers.failed
            || state.writers.terminal
            || epoch & 1 != 0
        {
            return Ok(None);
        }
        match self.claims.lookup::<_, NativeClaim>(key) {
            Ok(Some(current)) if current == *expected => {}
            Ok(_) => return Ok(None),
            Err(error) => {
                drop(state);
                return self.read_result(Err(error));
            }
        }
        Ok(checked_query(epoch, query, || {
            self.root.epoch().load(Ordering::SeqCst)
        }))
    }
    pub(crate) fn remove_claim(
        &self,
        key: &NativeKey,
        expected: &NativeClaim,
    ) -> anyhow::Result<()> {
        let state = self.state.lock();
        ensure!(
            state.writers.count != 0 && self.root.epoch().load(Ordering::SeqCst) & 1 == 0,
            "native claim removal requires a writer and drained capture ownership"
        );
        ensure!(
            expected.is_transit(key)
                && expected.state >> 4 == 0
                && matches!(
                    (expected.executor, expected.state & 15),
                    (NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED)
                        | (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ACTIVE)
                ),
            "Native removal retains unresolved original ownership"
        );
        let result = self.delete_claim(key, expected);
        drop(state);
        self.read_result(result)
    }

    fn delete_claim(&self, key: &NativeKey, expected: &NativeClaim) -> io::Result<()> {
        let Some(current) = self.claims.lookup::<_, NativeClaim>(key)? else {
            return Ok(());
        };
        if current != *expected {
            return Ok(());
        }
        match element(3, self.claims.fd(), key as *const NativeKey as u64, 0, 0) {
            Ok(_) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn claims(&self) -> anyhow::Result<NativeClaims> {
        #[cfg(test)]
        if self.test_closed && self.test_grace.load(Ordering::SeqCst) == 1 {
            return Ok(NativeClaims {
                entries: Vec::new(),
                _memory: reserve(&self.budget, PAGE_BYTES)?,
            });
        }
        ensure!(
            self.state.lock().writers.count != 0
                && self.root.epoch().load(Ordering::SeqCst) & 1 == 0,
            "native claim scan requires a closed writer"
        );
        self.scan_claims()
    }

    fn scan_claims(&self) -> anyhow::Result<NativeClaims> {
        let memory = reserve(
            &self.budget,
            (self.capacity as usize)
                .checked_mul(size_of::<(NativeKey, NativeClaim)>())
                .and_then(|bytes| bytes.checked_add(4 * PAGE_BYTES))
                .context("Native scan pair charge overflow")?,
        )?;
        let result = (|| -> io::Result<Vec<(NativeKey, NativeClaim)>> {
            let mut values = Vec::with_capacity(self.capacity as usize);
            let mut previous: Option<NativeKey> = None;
            let mut steps = 0usize;
            loop {
                let mut next = NativeKey::default();
                match element(
                    4,
                    self.claims.fd(),
                    previous
                        .as_ref()
                        .map_or(0, |key| key as *const NativeKey as u64),
                    &mut next as *mut NativeKey as u64,
                    0,
                ) {
                    Ok(_) => {}
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => break,
                    Err(error) => return Err(error),
                }
                steps += 1;
                if steps > self.capacity as usize * 2 {
                    return Err(io::Error::other(
                        "native claim scan failed to make progress",
                    ));
                }
                if values.len() == self.capacity as usize {
                    return Err(io::Error::other("native claim traversal did not terminate"));
                }
                if let Some(claim) = self.lookup_claim(&next)? {
                    values.push((next, claim));
                }
                previous = Some(next);
            }
            Ok(values)
        })();
        self.read_result(result).map(|entries| NativeClaims {
            entries,
            _memory: memory,
        })
    }

    /// Runtime calls only after RX, endpoints, scopes, CQ and every hook are joined.
    pub(crate) fn retire_closed_claims(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock();
        ensure!(
            state.writers.terminal
                && state.writers.count == 0
                && self.root.epoch().load(Ordering::SeqCst) & 1 == 0,
            "native terminal claim retirement requires closed joined owners"
        );
        if let Err(error) = self.drain_recorded(&mut state, NativeReason::Shutdown) {
            state.writers.failed = true;
            return Err(error.context("native terminal claim reader grace"));
        }
        drop(state);
        for (key, expected) in self.scan_claims()? {
            // Host source ownership can only retire through its bank and joined
            // source/output consumer, even after physical targets have stopped.
            if expected.owner_cookie != 0 {
                continue;
            }
            self.read_result(self.delete_claim(&key, &expected))?;
        }
        let remaining = self.scan_claims()?;
        let state = self.state.lock();
        let complete = remaining.iter().all(|(key, claim)| {
            claim.owner_cookie != 0
                && state.hosts.iter().any(|host| {
                    host.target.namespace == key.namespace_cookie
                        && host.target.attachment == claim.attachment_generation
                        && host
                            .target
                            .retained_sources()
                            .is_some_and(|count| count != 0)
                })
        });
        drop(state);
        self.read_result(if complete {
            Ok(())
        } else {
            Err(io::Error::other(
                "native terminal claims remain without guarded source custody",
            ))
        })
    }
}

pub(crate) struct NativeClaims {
    entries: Vec<(NativeKey, NativeClaim)>,
    _memory: MemoryReservation,
}
impl std::ops::Deref for NativeClaims {
    type Target = [(NativeKey, NativeClaim)];
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}
pub(crate) struct NativeClaimsIter {
    entries: std::vec::IntoIter<(NativeKey, NativeClaim)>,
    _memory: MemoryReservation,
}
impl Iterator for NativeClaimsIter {
    type Item = (NativeKey, NativeClaim);
    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next()
    }
}
impl IntoIterator for NativeClaims {
    type Item = (NativeKey, NativeClaim);
    type IntoIter = NativeClaimsIter;
    fn into_iter(self) -> Self::IntoIter {
        NativeClaimsIter {
            entries: self.entries.into_iter(),
            _memory: self._memory,
        }
    }
}

impl Drop for NativePublication {
    fn drop(&mut self) {
        #[cfg(test)]
        if self.test_closed && self.test_grace.load(Ordering::SeqCst) == 0 {
            return;
        }
        #[cfg(test)]
        let retain_kernel_charges = !self.test_closed;
        #[cfg(not(test))]
        let retain_kernel_charges = true;
        if retain_kernel_charges {
            for map in [&mut self.root.map, &mut self.claims, &mut self.scratch] {
                for charge in map._memory.drain(..) {
                    std::mem::forget(charge);
                }
            }
            for charge in self._memory.drain(..) {
                std::mem::forget(charge);
            }
        }
        let mut state = self.state.lock();
        if state.recording.completed {
            if retain_kernel_charges {
                state.retain_kernel_charges();
            }
            return;
        }
        state.writers.terminal = true;
        let epoch = self.root.epoch().load(Ordering::SeqCst);
        let operation = state.recording.operation();
        if let Err(error) = self.close_recorded(
            &mut state,
            epoch.saturating_add(epoch & 1) & !1,
            operation,
            0,
            NativeReason::OwnerDrop,
            true,
        ) {
            tracing::error!(%error, "native terminal reader grace failed");
        }
        let snapshot = self.recording_snapshot(&state, false);
        let result = state.recording.export(false, snapshot);
        result.record();
        if retain_kernel_charges {
            state.retain_kernel_charges();
        }
    }
}

fn next_closed(epoch: u64) -> Option<u64> {
    epoch.checked_add(if epoch & 1 != 0 { 1 } else { 2 })
}

fn scan_claim_candidates(
    capacity: u32,
    current_epoch: impl Fn() -> u64,
    mut next_key: impl FnMut(Option<&NativeKey>) -> io::Result<Option<NativeKey>>,
    mut lookup: impl FnMut(&NativeKey) -> io::Result<Option<NativeClaim>>,
    mut candidate: impl FnMut(&NativeKey, &NativeClaim) -> bool,
) -> io::Result<bool> {
    let epoch = current_epoch();
    if epoch & 1 == 0 {
        return Ok(true);
    }
    let mut previous = None;
    for _ in 0..u64::from(capacity) * 2 {
        let Some(key) = next_key(previous.as_ref())? else {
            // Open readers only insert or refresh activity. Every deletion crosses
            // a closed epoch, so only unchanged open traversal can be negative.
            return Ok(current_epoch() != epoch);
        };
        let Some(claim) = lookup(&key)? else {
            return Ok(true);
        };
        if candidate(&key, &claim) {
            return Ok(true);
        }
        previous = Some(key);
    }
    Ok(true)
}

fn checked_query(
    epoch: u64,
    query: impl FnOnce() -> io::Result<bool>,
    current_epoch: impl FnOnce() -> u64,
) -> Option<bool> {
    let owned = query().ok()?;
    (epoch == current_epoch()).then_some(owned)
}

struct ClockSample {
    boot: u64,
    now: tokio::time::Instant,
    offset: (i128, i128),
}
pub(crate) fn kernel_monotonic_ns(namespaced_ns: u64, offset_ns: i128) -> anyhow::Result<u64> {
    i128::from(namespaced_ns)
        .checked_sub(offset_ns)
        .and_then(|value| u64::try_from(value).ok())
        .context("native kernel monotonic clock overflow")
}

fn clock_ns(kind: libc::clockid_t) -> anyhow::Result<u64> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(kind, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let value = unsafe { value.assume_init() };
    ensure!(
        value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
        "invalid native clock sample"
    );
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(value.tv_nsec as u64))
        .context("native clock overflow")
}
fn sample_clock() -> anyhow::Result<ClockSample> {
    let before = clock_ns(libc::CLOCK_MONOTONIC)?;
    let boot = clock_ns(libc::CLOCK_BOOTTIME)?;
    let after = clock_ns(libc::CLOCK_MONOTONIC)?;
    // BOOTTIME precedes Tokio: delayed sampling can shorten a deadline, never extend it.
    let now = tokio::time::Instant::now();
    Ok(ClockSample {
        boot,
        now,
        offset: (boot as i128 - after as i128, boot as i128 - before as i128),
    })
}

/// The emitted rule ID is sufficient only while every earlier decision can be
/// reproduced from the confirmed connection's original tuple. Missing reply
/// DNS/process/MAC/DSCP facts must never manufacture a terminal Block result.
fn reply_block_rules(plan: &RoutingPushPlan) -> Vec<u32> {
    let mut proven = Vec::with_capacity(plan.rules.len() + 1);
    for rule in &plan.rules {
        if rule.folded_false() {
            continue;
        }
        let mut conditional = false;
        for (_, condition) in rule.runtime_conditions() {
            conditional = true;
            if !matches!(
                &condition.predicate,
                KernelPredicate::DestinationIp(_)
                    | KernelPredicate::SourceIp(_)
                    | KernelPredicate::DestinationPort(_)
                    | KernelPredicate::SourcePort(_)
                    | KernelPredicate::Protocol(_)
                    | KernelPredicate::IpVersion(_)
            ) {
                return proven;
            }
        }
        if rule.action.outbound == honk_ebpf_common::OutboundIndex::Block as u8 {
            proven.push(rule.id);
        }
        if !conditional {
            return proven;
        }
    }
    if plan.fallback.outbound == honk_ebpf_common::OutboundIndex::Block as u8 {
        proven.push(u32::MAX);
    }
    proven
}

fn admit_physical_effects(plan: &RoutingPushPlan) -> anyhow::Result<()> {
    ensure!(
        plan.fallback.mark.is_none() && plan.rules.iter().all(|rule| rule.action.mark.is_none()),
        "physical Native targets support only Keep traffic marks"
    );
    Ok(())
}

fn compiler_bytes(plan: &RoutingPushPlan, captured: bool) -> anyhow::Result<usize> {
    let mut instructions = 4096usize;
    let mut source_bytes = 0usize;
    for rule in &plan.rules {
        source_bytes = source_bytes
            .checked_add(rule.source.len())
            .context("native compiler source overflow")?;
        instructions = instructions.saturating_add(256);
        for condition in &rule.conditions {
            let predicate = match &condition.predicate {
                KernelPredicate::DestinationPort(ranges) | KernelPredicate::SourcePort(ranges) => {
                    ranges.len().saturating_mul(8)
                }
                KernelPredicate::Dscp(values) => values.len(),
                KernelPredicate::ProcessName(names) => names.iter().fold(0usize, |sum, name| {
                    sum.saturating_add(
                        (honk_ebpf_common::ROUTING_PROCESS_MAX_LEN.saturating_sub(name.len()) + 1)
                            .saturating_mul(name.len().saturating_mul(2).saturating_add(8))
                            .saturating_add(16),
                    )
                }),
                _ => 0,
            };
            instructions = instructions.saturating_add(256).saturating_add(predicate);
        }
    }
    // The canonical emitter stops at one million instructions. Include vector
    // growth, labels/fixups, loader copies, verifier diagnostics and JIT staging.
    let instructions = instructions.min(1_000_000);
    let captured_instructions = if captured {
        instructions
            .checked_add(4096)
            .context("captured compiler bound overflow")?
    } else {
        0
    };
    instructions
        .checked_add(captured_instructions)
        .and_then(|count| count.checked_mul(256))
        .and_then(|bytes| bytes.checked_add(4 << 20))
        .and_then(|bytes| {
            source_bytes
                .checked_mul(3)
                .and_then(|source| bytes.checked_add(source))
        })
        .context("native compiler charge overflow")
}
fn plan_bytes(plan: &RoutingPushPlan) -> anyhow::Result<usize> {
    let mut bytes = size_of::<RoutingPushPlan>() + 4 * PAGE_BYTES;
    for entries in [
        &plan.facts.destination_v4,
        &plan.facts.destination_v6,
        &plan.facts.source_v4,
        &plan.facts.source_v6,
        &plan.facts.mac,
    ] {
        bytes = bytes
            .checked_add(
                entries
                    .len()
                    .checked_mul(size_of::<(LpmKey, DomainRouting)>())
                    .context("native plan size overflow")?,
            )
            .context("native plan size overflow")?;
    }
    for rule in &plan.rules {
        let mut rule_bytes = size_of_val(rule)
            + rule.source.len()
            + rule.conditions.len() * size_of::<crate::control::routing_matcher::KernelCondition>();
        for condition in &rule.conditions {
            rule_bytes += match &condition.predicate {
                KernelPredicate::DestinationPort(values) | KernelPredicate::SourcePort(values) => {
                    values.len() * size_of::<crate::routing::PortRange>()
                }
                KernelPredicate::Dscp(values) => values.len(),
                KernelPredicate::ProcessName(names) => {
                    names.len() * size_of::<Vec<u8>>() + names.iter().map(Vec::len).sum::<usize>()
                }
                _ => 0,
            };
        }
        bytes = bytes
            .checked_add(rule_bytes)
            .context("native plan size overflow")?;
    }
    bytes.checked_mul(3).context("native plan charge overflow")
}

#[cfg(test)]
mod tests {
    use super::{Writers, next_closed};

    #[tokio::test]
    async fn native_capture_proof_into_admission_requires_the_exact_candidate() {
        use super::*;
        use crate::control::core_forward::CapturedDecision;
        use crate::control::netstack::{CAPTURE_MEMORY, capture_scope};
        use crate::control::packet_endpoint::PacketEndpoints;
        use honk_datapath::forward::{Ingress, MarkProvenance, RouteQuery};
        use std::future::poll_fn;
        use std::time::{Duration, Instant};

        tokio::time::timeout(Duration::from_secs(10), async {
            let budget = MemoryBudget::new(CAPTURE_MEMORY);
            let (scope, scope_owner) = capture_scope(1500, 1, 8, &budget).unwrap();
            let mut config = honk_config::Config::default();
            config.ensure_builtin_nodes();
            config.global.dial_mode = "ip".into();
            config.global.nfqueue_enable = false;
            config.global.tcp_check_url.clear();
            config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
            config.global.preconnect_node_count = 0;
            config.global.udp_warm_node_count = 0;
            config.routing.default_outbound = "direct".into();
            config.routing.default_must = false;
            config.datapath = Some(honk_config::datapath::DatapathConfig {
                backend: honk_config::datapath::Backend::Xdp,
                direct: Some(honk_config::datapath::DirectProfile::Native),
                interfaces: vec![honk_config::datapath::XdpInterface {
                    name: "dut0".into(),
                    role: honk_config::datapath::InterfaceRole::Lan,
                }],
                ..Default::default()
            });
            let mut plane = crate::control::tests::support::control_plane(config);
            plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
                crate::mode::ModeState::new("Rule", "direct"),
            )));
            plane.start_datapath_flags_coordinator().unwrap();
            let authority = plane.native_packet_policy().await.unwrap();
            let (endpoints, mut owner, mut drivers) = PacketEndpoints::start_driven(
                plane,
                vec![(scope.clone(), scope_owner)],
                4,
                None,
                ScopeId::HOST,
            )
            .await
            .unwrap();
            poll_fn(|cx| {
                for driver in &mut drivers {
                    driver.service(cx, Instant::now());
                }
                owner.poll_ready(cx)
            })
            .await
            .unwrap();
            assert_eq!(drivers.len(), 1);

            let facts = scope.scope();
            let routing_scope = ScopeId::allocate().unwrap();
            let ingress = Ingress {
                scope: routing_scope,
                namespace: 1,
                ifindex: 2,
                attachment: 13,
                mark: MarkProvenance::BeforeSkb,
            };
            let query = RouteQuery {
                ingress,
                source: "192.0.2.1".parse().unwrap(),
                destination: "198.51.100.2".parse().unwrap(),
                traffic_class: 0,
                protocol: 17,
                ports: Some((40000, 53)),
            };
            let imported = ImportedOriginal {
                identity: NativeClaimIdentity {
                    key: NativeKey {
                        src_ip: super::super::maps::ip_addr_to_lpm_key(query.source).data,
                        dst_ip: super::super::maps::ip_addr_to_lpm_key(query.destination).data,
                        src_port: 40000_u16.to_be(),
                        dst_port: 53_u16.to_be(),
                        l4proto: 17,
                        ip_version: 4,
                        domain: NATIVE_DOMAIN_FLOW,
                        direction: NATIVE_DIRECTION_ORIGINAL,
                        namespace_cookie: ingress.namespace,
                        zone: 0,
                        zone_state: NATIVE_ZONE_TRANSIT_DEFAULT,
                        reserved: [0; 5],
                    },
                    epoch: 3,
                    incarnation: 3,
                    scope: facts.as_u64(),
                },
                producer: NativeImport {
                    epoch: 3,
                    incarnation: 3,
                    expires_boottime_ns: u64::MAX,
                    flags: NATIVE_IMPORT_COUNTED,
                    reserved: 0,
                },
                executor: NATIVE_EXECUTOR_PENDING,
                state: 16 | NATIVE_PHASE_PENDING,
            };
            assert!(imported.identity.key.is_valid());
            let (first, second, positive) = {
                let read = authority.try_read_policy().unwrap();
                let classify = |candidate| {
                    let original = NativeOriginal {
                        imported: &imported,
                        authority: CaptureAuthority {
                            namespace_cookie: ingress.namespace,
                            attachment_generation: ingress.attachment,
                            scope: ingress.scope.as_u64(),
                            config_generation: 1,
                            ifindex: ingress.ifindex,
                            reserved: 0,
                        },
                        ingress,
                        facts,
                        realm_index: 0,
                        rx_queue: 0,
                        extent: OriginalExtent {
                            frame_length: 60,
                            l3_offset: 14,
                            l3_length: 28,
                            vlan_tci: [0; 2],
                            vlan_proto: [0; 2],
                            vlan_count: 0,
                            inline_vlan_count: 0,
                            dscp: 0,
                        },
                        basis_epoch: 3,
                        basis_flags: 0,
                        retained_capture: false,
                        candidate,
                    };
                    authority
                        .capture_original(&read, query, facts, &original, &budget)
                        .unwrap()
                };
                assert!(
                    matches!(classify(0), CapturedDecision::Refuse),
                    "candidate zero cannot authorize a first consumer"
                );
                let CapturedDecision::Endpoint(first) = classify(1) else {
                    panic!("ordinary controller DNS must produce Endpoint admission");
                };
                let CapturedDecision::Endpoint(second) = classify(2) else {
                    panic!("second DNS candidate must use the same Endpoint path");
                };
                let CapturedDecision::Endpoint(positive) = classify(3) else {
                    panic!("matching-proof control needs an actual Endpoint candidate");
                };
                (first, second, positive)
            };
            assert_ne!(first.basis().candidate, second.basis().candidate);
            assert_eq!(
                NativeCaptureBasis {
                    candidate: first.basis().candidate,
                    ..*second.basis()
                },
                *first.basis(),
                "the candidate identity alone must distinguish these admissions"
            );
            let wrong_candidate = CaptureProof {
                candidate: first.basis().candidate,
                basis: *first.basis(),
            };
            let error = second
                .into_admission(wrong_candidate)
                .expect_err("a proof for another candidate must be rejected by into_admission");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            drop(first);
            let matching = CaptureProof {
                candidate: positive.basis().candidate,
                basis: *positive.basis(),
            };
            let admission = positive
                .into_admission(matching)
                .expect("the same candidate's proof must admit after classification guards drop");
            drop(admission);
            drop(authority);

            endpoints.close();
            let (_plane, result) = poll_fn(|cx| {
                for driver in &mut drivers {
                    driver.service(cx, Instant::now());
                }
                owner.poll_join_plane(cx)
            })
            .await
            .unwrap();
            result.unwrap();
        })
        .await
        .expect("candidate admission fixture must join its actual endpoint owner");
    }

    fn entered_grace_publication_fixture()
    -> (std::sync::Arc<super::NativePublication>, tempfile::TempDir) {
        use super::*;
        let directory = tempfile::tempdir().unwrap();
        let (publication, basis) = publication_basis_fixture_with_export(Some(directory.path()));
        let cell = stale_only_captured_cell(&publication);
        let writer = publication.write(NativeReason::RuntimeMaintenance).unwrap();
        let op_incarnation = writer.epoch();
        writer.commit();
        let expected_epoch = publication.selection_epoch().unwrap();
        let entry_seq = 77;
        let prepared = PreparedOriginal {
            identity: basis.identity,
            op_incarnation,
            return_attachment: cell.return_attachment().as_u64(),
            expected_epoch,
            expires_boottime_ns: basis.producer.expires_boottime_ns,
        };
        let record = NativeCapturedOperation {
            op_incarnation,
            return_attachment: prepared.return_attachment,
            ingress_attachment: 13,
            claim_epoch: basis.identity.epoch,
            claim_incarnation: basis.identity.incarnation,
            claim_scope: basis.identity.scope,
            capture_epoch: basis.producer.epoch,
            basis_epoch: expected_epoch,
            expires_boottime_ns: basis.producer.expires_boottime_ns,
            routing_generation: basis.routing_generation,
            mode_revision: basis.mode_revision,
            fact_scope: basis.fact_scope.as_u64(),
            fact_revision: basis.fact_revision,
            fact_horizon: u64::MAX,
            key: basis.identity.key,
            ingress_ifindex: 2,
            logical_ifindex: 2,
            realm_index: 0,
            frame_length: 64,
            l3_offset: 14,
            l3_length: 50,
            flags: basis.producer.flags,
            receipt: 1,
            entry_seq,
            ..Default::default()
        };
        unsafe {
            cell.0.mapping.as_ptr().write_volatile(record);
        }
        cell.0.phase().store(NATIVE_OP_ENTERED, Ordering::Release);
        let observation = cell.observe(&prepared).unwrap();
        assert_eq!(observation.phase, NATIVE_OP_ENTERED);
        assert_eq!(observation.entry_seq, entry_seq);
        let mut receipt = {
            let state = publication.state.lock();
            basis_receipt(&basis, &state, "OPERATION_PREPARED")
        };
        receipt.basis_epoch = Some(expected_epoch);
        receipt.return_attachment = Some(prepared.return_attachment);
        receipt.slot = Some(0);
        receipt.op_incarnation = Some(op_incarnation);
        let inventory_memory = reserve(&publication.budget, PAGE_BYTES).unwrap();
        publication.state.lock().captured = Some(CapturedBinding {
            cell,
            programs: None,
            operation: Some(op_incarnation),
            receipt: Some(receipt),
            grace_entry: 0,
            grace_done: 0,
            grace_recorded: false,
            _inventory_memory: inventory_memory,
        });
        publication.quiesce(NativeReason::Shutdown).unwrap();
        assert!(publication.selection_epoch().is_none());
        assert!(publication.state.lock().writers.terminal);
        (publication, directory)
    }

    fn exported_original_grace_receipts(
        publication: &super::NativePublication,
    ) -> Vec<serde_json::Value> {
        let result = publication.export_recording(false, false);
        assert!(result.error.is_none(), "{:?}", result.error);
        let artifact: serde_json::Value = serde_json::from_slice(
            &std::fs::read(result.path.expect("recording export path")).unwrap(),
        )
        .unwrap();
        artifact["captured_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt["kind"].as_str(),
                    Some("ENTRY_ACQUIRED" | "FRESH_GRACE_STARTED" | "FRESH_GRACE_DONE")
                )
            })
            .cloned()
            .collect()
    }

    fn original_grace_proof_state(publication: &super::NativePublication) -> (u64, u64, bool) {
        let state = publication.state.lock();
        let binding = state.captured.as_ref().unwrap();
        assert!(binding.operation.is_some());
        (
            binding.grace_entry,
            binding.grace_done,
            binding.grace_recorded,
        )
    }

    #[test]
    fn native_original_grace_records_first_proof_once_after_quiesce() {
        let (publication, _directory) = entered_grace_publication_fixture();
        let closed_epoch = publication.epoch_for_test();
        publication.original_grace().unwrap();
        let first = exported_original_grace_receipts(&publication);
        assert_eq!(first.len(), 3);
        assert_eq!(
            first
                .iter()
                .map(|receipt| receipt["kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["ENTRY_ACQUIRED", "FRESH_GRACE_STARTED", "FRESH_GRACE_DONE"]
        );
        let sequence = |index: usize| {
            first[index]["seq"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        };
        assert!(sequence(0) < sequence(1) && sequence(1) < sequence(2));
        assert_eq!(first[0]["entry_seq"], "77");
        assert_eq!(first[1]["related_seq"], first[0]["seq"]);
        assert_eq!(first[2]["related_seq"], first[1]["seq"]);
        assert_eq!(first[2]["fresh_grace"], true);
        for receipt in &first {
            assert_eq!(receipt["key"], first[0]["key"]);
            for field in [
                "claim_epoch",
                "claim_incarnation",
                "claim_scope",
                "return_attachment",
                "op_incarnation",
                "slot",
                "basis_epoch",
            ] {
                assert!(!receipt[field].is_null(), "{field}");
                assert_eq!(receipt[field], first[0][field], "{field}");
            }
        }
        let proof = original_grace_proof_state(&publication);
        assert_eq!(proof, (77, sequence(2), true));
        publication.original_grace().unwrap();
        assert_eq!(exported_original_grace_receipts(&publication), first);
        assert_eq!(original_grace_proof_state(&publication), proof);
        publication.set_grace_failure_for_test(true);
        let error = publication.original_grace().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected native reader grace failure"),
            "{error:#}"
        );
        assert_eq!(exported_original_grace_receipts(&publication), first);
        assert_eq!(original_grace_proof_state(&publication), proof);
        assert_eq!(publication.epoch_for_test(), closed_epoch);
        assert!(publication.selection_epoch().is_none());
    }

    #[test]
    fn native_original_grace_first_failure_cannot_gain_proof_on_later_poll() {
        use super::*;
        let (publication, _directory) = entered_grace_publication_fixture();
        publication.set_grace_failure_for_test(true);
        let error = publication.original_grace().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected native reader grace failure"),
            "{error:#}"
        );
        assert_eq!(original_grace_proof_state(&publication), (0, 0, true));
        let failed = exported_original_grace_receipts(&publication);
        assert_eq!(failed.len(), 3);
        assert_eq!(
            failed
                .iter()
                .map(|receipt| receipt["kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["ENTRY_ACQUIRED", "FRESH_GRACE_STARTED", "FRESH_GRACE_DONE"]
        );
        assert_eq!(failed[2]["fresh_grace"], false);
        publication.set_grace_failure_for_test(false);
        publication
            .test_grace_observed_epoch
            .store(0, Ordering::SeqCst);
        let later = publication.original_grace().unwrap_err();
        assert_eq!(
            later.to_string(),
            "captured original first completion grace failed; retaining ownership"
        );
        assert_eq!(
            publication.test_grace_observed_epoch.load(Ordering::SeqCst),
            publication.epoch_for_test(),
            "sticky failure must not skip a later reader barrier"
        );
        assert_eq!(original_grace_proof_state(&publication), (0, 0, true));
        assert_eq!(exported_original_grace_receipts(&publication), failed);
        assert!(publication.selection_epoch().is_none());
    }

    #[test]
    fn native_capture_proof_rejects_an_identical_basis_from_another_candidate() {
        use super::*;
        let (_, first) = publication_basis_fixture();
        let second = NativeCaptureBasis {
            candidate: first.candidate + 1,
            ..first
        };
        let proof = CaptureProof {
            candidate: first.candidate,
            basis: first,
        };
        assert!(proof.matches(&first));
        assert!(!proof.matches(&second));
        assert!(
            !CaptureProof {
                candidate: 0,
                basis: first
            }
            .matches(&NativeCaptureBasis {
                candidate: 0,
                ..first
            })
        );
        assert!(!proof.matches(&NativeCaptureBasis {
            mode_revision: first.mode_revision + 1,
            ..first
        }));
    }

    fn publication_basis_fixture() -> (
        std::sync::Arc<super::NativePublication>,
        super::NativeCaptureBasis,
    ) {
        publication_basis_fixture_with_export(None)
    }

    fn publication_basis_fixture_with_export(
        export: Option<&std::path::Path>,
    ) -> (
        std::sync::Arc<super::NativePublication>,
        super::NativeCaptureBasis,
    ) {
        use super::*;
        use crate::control::routing_matcher::KernelAction;
        let publication = recorded_publication();
        if let Some(path) = export {
            publication.initialize_export(path).unwrap();
        }
        let scope = ScopeId::allocate().unwrap();
        let key = NativeKey {
            src_ip: super::super::maps::ip_addr_to_lpm_key("192.0.2.1".parse().unwrap()).data,
            dst_ip: super::super::maps::ip_addr_to_lpm_key("198.51.100.1".parse().unwrap()).data,
            src_port: 12345_u16.to_be(),
            dst_port: 443_u16.to_be(),
            l4proto: 17,
            ip_version: 4,
            namespace_cookie: 11,
            zone_state: NATIVE_ZONE_TRANSIT_DEFAULT,
            ..Default::default()
        };
        let expiry = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(3600));
        {
            let mut state = publication.state.lock();
            state.plan = Some(RoutingPushPlan {
                rules: Vec::new(),
                facts: Default::default(),
                fallback: KernelAction {
                    outbound: honk_ebpf_common::OutboundIndex::Direct as u8,
                    must: false,
                    mark: None,
                    direct_mark_index: None,
                },
                features: 0,
                fingerprint: [3; 32],
                policy_fingerprint: [3; 32],
                has_domain_rules: false,
                domain_predicate_count: 0,
                trace_enabled: false,
            });
            state.scopes.insert(
                scope,
                Scope {
                    revision: 7,
                    generation: 4,
                    fingerprint: [3; 32],
                    facts: vec![(key.dst_ip, DomainRouting::default(), u64::MAX, expiry)],
                    _memory: reserve(&publication.budget, 512).unwrap(),
                },
            );
        }
        publication.write(NativeReason::Startup).unwrap().commit();
        let basis = NativeCaptureBasis {
            candidate: 1,
            identity: NativeClaimIdentity {
                key,
                epoch: 3,
                incarnation: 3,
                scope: scope.as_u64(),
            },
            basis_epoch: publication.selection_epoch().unwrap(),
            routing_generation: 4,
            fingerprint: [3; 32],
            mode_revision: 9,
            flags: publication.root.flags().load(Ordering::Acquire),
            fact_scope: scope,
            fact_revision: 7,
            fact_horizon: expiry,
            producer: NativeImport {
                epoch: 3,
                incarnation: 3,
                expires_boottime_ns: u64::MAX,
                flags: NATIVE_IMPORT_COUNTED,
                reserved: 0,
            },
        };
        assert!(key.is_valid());
        (publication, basis)
    }

    fn publication_selection(executor: u32, phase: u32, count: u32) -> super::NativeClaim {
        use super::*;
        let packed = native_selection(executor, phase, count).unwrap();
        NativeClaim {
            epoch: 3,
            incarnation: 3,
            scope: 1,
            executor,
            state: (packed >> 32) as u32,
            ..Default::default()
        }
    }

    #[test]
    fn native_capture_candidate_stale_after_guard_drop_reclassifies_without_closing() {
        use super::*;
        for case in [
            "epoch",
            "identity",
            "flags",
            "generation",
            "revision",
            "fingerprint",
            "scope",
            "expired",
            "horizon",
        ] {
            let (publication, mut basis) = publication_basis_fixture();
            let expected = basis.identity;
            let fact_scope = basis.fact_scope;
            match case {
                "epoch" => publication.write(NativeReason::Policy).unwrap().commit(),
                "identity" => basis.identity.incarnation += 2,
                "flags" => basis.flags ^= 1,
                "generation" => basis.routing_generation += 1,
                "revision" => basis.fact_revision += 1,
                "fingerprint" => basis.fingerprint[0] ^= 1,
                "scope" => basis.fact_scope = ScopeId::allocate().unwrap(),
                "expired" => {
                    basis.fact_horizon = Some(tokio::time::Instant::now());
                    publication
                        .state
                        .lock()
                        .scopes
                        .get_mut(&basis.fact_scope)
                        .unwrap()
                        .facts[0]
                        .3 = basis.fact_horizon;
                }
                "horizon" => basis.fact_horizon = None,
                _ => unreachable!(),
            }
            let before = publication.selection_epoch().unwrap();
            let error = publication
                .commit_capture(&expected, &basis)
                .err()
                .expect(case);
            assert_eq!(
                error.downcast_ref::<io::Error>().map(io::Error::kind),
                Some(io::ErrorKind::WouldBlock),
                "{case}: {error:#}"
            );
            assert_eq!(publication.selection_epoch(), Some(before + 2), "{case}");
            {
                let state = publication.state.lock();
                assert_eq!(state.writers.count, 0, "{case}");
                assert!(!state.writers.failed && !state.writers.terminal, "{case}");
                assert_eq!(state.scopes[&fact_scope].revision, 7, "{case}");
            }
            let events = publication.recording_events_for_test();
            assert!(
                events
                    .iter()
                    .rev()
                    .any(|event| event.kind == NATIVE_EVENT_WRITER_OUTCOME
                        && event.outcome == NATIVE_OUTCOME_COMMITTED),
                "{case}"
            );
            publication
                .write(NativeReason::RuntimeMaintenance)
                .unwrap()
                .commit();
            assert!(publication.selection_epoch().is_some(), "{case}");
        }
    }

    #[test]
    fn native_counted_completion_covers_every_rx_exit() {
        use super::*;
        // The opaque RxCompletion requires a real Port. This matrix protects the
        // shared settlement rules, not the Runtime exits' routing into them.
        for (exit, executor, phase, next_phase) in [
            (
                "Endpoint takeover",
                NATIVE_EXECUTOR_CAPTURE,
                NATIVE_PHASE_CAPTURE_COMMITTED,
                NATIVE_PHASE_CAPTURE_COMMITTED,
            ),
            (
                "Core takeover",
                NATIVE_EXECUTOR_CAPTURE,
                NATIVE_PHASE_CAPTURE_COMMITTED,
                NATIVE_PHASE_CAPTURE_COMMITTED,
            ),
            (
                "early disposal",
                NATIVE_EXECUTOR_PENDING,
                NATIVE_PHASE_PENDING,
                NATIVE_PHASE_PENDING,
            ),
            (
                "callback error disposal",
                NATIVE_EXECUTOR_PENDING,
                NATIVE_PHASE_PENDING,
                NATIVE_PHASE_PENDING,
            ),
            (
                "poll_io closing",
                NATIVE_EXECUTOR_PENDING,
                NATIVE_PHASE_CLOSING,
                NATIVE_PHASE_CLOSING,
            ),
            (
                "drain_native_originals",
                NATIVE_EXECUTOR_CAPTURE,
                NATIVE_PHASE_CLOSING,
                NATIVE_PHASE_CLOSING,
            ),
            (
                "terminal cleanup",
                NATIVE_EXECUTOR_KERNEL,
                NATIVE_PHASE_CLOSING,
                NATIVE_PHASE_CLOSING,
            ),
            (
                "returned original",
                NATIVE_EXECUTOR_KERNEL,
                NATIVE_PHASE_ARMED,
                NATIVE_PHASE_DRAINING,
            ),
        ] {
            let mut claim = publication_selection(executor, phase, 2);
            let original = claim;
            settle_selection(
                &mut claim,
                NATIVE_IMPORT_COUNTED,
                OriginalInventory {
                    first_ordered: true,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(claim.state, (1 << 4) | next_phase, "{exit}");
            assert_eq!(
                NativeClaim {
                    state: original.state,
                    ..claim
                },
                original,
                "{exit}"
            );
        }
        for (name, mut claim, flags) in [
            (
                "credit underflow",
                publication_selection(NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED, 0),
                NATIVE_IMPORT_COUNTED,
            ),
            (
                "unknown flag",
                publication_selection(NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED, 1),
                NATIVE_IMPORT_COUNTED | 2,
            ),
            (
                "Active completion",
                publication_selection(NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ACTIVE, 0),
                0,
            ),
        ] {
            let before = claim;
            assert!(
                settle_selection(&mut claim, flags, OriginalInventory::default()).is_err(),
                "{name}"
            );
            assert_eq!(claim, before, "{name}");
        }
    }

    #[test]
    fn native_capture_cross_queue_uncounted_cannot_spend_old_credit() {
        use super::*;
        let mut claim =
            publication_selection(NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED, 2);
        for (flags, expected) in [
            (0, 2),
            (0, 2),
            (NATIVE_IMPORT_COUNTED, 1),
            (0, 1),
            (0, 1),
            (NATIVE_IMPORT_COUNTED, 0),
            (0, 0),
        ] {
            settle_selection(&mut claim, flags, OriginalInventory::default()).unwrap();
            assert_eq!(claim.state >> 4, expected);
            assert_eq!(claim.executor, NATIVE_EXECUTOR_CAPTURE);
            assert_eq!(claim.state & 15, NATIVE_PHASE_CAPTURE_COMMITTED);
        }
        assert_eq!(claim.state, NATIVE_PHASE_CAPTURE_COMMITTED);
    }

    #[test]
    fn native_active_requires_ordered_zero_and_empty_original_owners() {
        use super::*;
        let empty_ordered = OriginalInventory {
            first_ordered: true,
            ..Default::default()
        };
        for phase in [NATIVE_PHASE_ARMED, NATIVE_PHASE_DRAINING] {
            for (barrier, count, inventory, next_phase) in [
                (
                    "positive order absent",
                    1,
                    OriginalInventory::default(),
                    phase,
                ),
                (
                    "outstanding redirect",
                    2,
                    empty_ordered,
                    NATIVE_PHASE_DRAINING,
                ),
                (
                    "held original",
                    1,
                    OriginalInventory {
                        held: 1,
                        ..empty_ordered
                    },
                    NATIVE_PHASE_DRAINING,
                ),
                (
                    "pending import/completion",
                    1,
                    OriginalInventory {
                        pending: 1,
                        ..empty_ordered
                    },
                    NATIVE_PHASE_DRAINING,
                ),
                (
                    "private flight",
                    1,
                    OriginalInventory {
                        flight: true,
                        ..empty_ordered
                    },
                    NATIVE_PHASE_DRAINING,
                ),
            ] {
                let mut claim = publication_selection(NATIVE_EXECUTOR_KERNEL, phase, count);
                settle_selection(&mut claim, NATIVE_IMPORT_COUNTED, inventory).unwrap();
                assert_eq!(claim.state & 15, next_phase, "{phase}: {barrier}");
                assert_eq!(claim.state >> 4, count - 1, "{phase}: {barrier}");
            }
            let mut claim = publication_selection(NATIVE_EXECUTOR_KERNEL, phase, 1);
            settle_selection(&mut claim, NATIVE_IMPORT_COUNTED, empty_ordered).unwrap();
            assert_eq!(claim.state, NATIVE_PHASE_ACTIVE);
        }
        for (executor, phase) in [
            (NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED),
            (NATIVE_EXECUTOR_PENDING, NATIVE_PHASE_PENDING),
            (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_CLOSING),
        ] {
            let mut claim = publication_selection(executor, phase, 1);
            settle_selection(&mut claim, NATIVE_IMPORT_COUNTED, empty_ordered).unwrap();
            assert_eq!(claim.state, phase);
            assert_eq!(claim.executor, executor);
        }
    }

    fn stale_only_captured_cell(publication: &super::NativePublication) -> super::CapturedCell {
        use super::*;
        // No program may use these unused FDs; only the preceding stale-basis path
        // is exercised, matching the existing closed_for_test map convention.
        let bytes = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(bytes > 0);
        let bytes = bytes as usize;
        let memory = reserve(&publication.budget, bytes).unwrap();
        let root = std::fs::File::open("/dev/null").unwrap().into();
        let map = Map {
            fd: std::fs::File::open("/dev/null").unwrap().into(),
            _memory: Vec::new(),
        };
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        CapturedCell(Arc::new(CapturedMapping {
            root,
            map,
            mapping: NonNull::new(pointer.cast()).unwrap(),
            bytes,
            attachment: ScopeId::allocate().unwrap(),
            _memory: memory,
        }))
    }

    #[test]
    fn native_prepare_requires_exact_open_epoch_and_original_horizon() {
        use super::*;
        let (publication, basis) = publication_basis_fixture();
        let writer = publication.write(NativeReason::RuntimeMaintenance).unwrap();
        {
            let mut state = publication.state.lock();
            assert!(publication.basis_is_current(&state, &writer, &basis));
            for (guard, changed) in [
                (
                    "exact preceding open epoch",
                    NativeCaptureBasis {
                        basis_epoch: basis.basis_epoch - 2,
                        ..basis
                    },
                ),
                (
                    "epoch overflow",
                    NativeCaptureBasis {
                        basis_epoch: u64::MAX,
                        ..basis
                    },
                ),
                (
                    "flags",
                    NativeCaptureBasis {
                        flags: basis.flags ^ 1,
                        ..basis
                    },
                ),
                (
                    "generation",
                    NativeCaptureBasis {
                        routing_generation: basis.routing_generation + 1,
                        ..basis
                    },
                ),
                (
                    "revision",
                    NativeCaptureBasis {
                        fact_revision: basis.fact_revision + 1,
                        ..basis
                    },
                ),
                (
                    "fingerprint",
                    NativeCaptureBasis {
                        fingerprint: [4; 32],
                        ..basis
                    },
                ),
                (
                    "scope",
                    NativeCaptureBasis {
                        fact_scope: ScopeId::allocate().unwrap(),
                        ..basis
                    },
                ),
                (
                    "original horizon identity",
                    NativeCaptureBasis {
                        fact_horizon: None,
                        ..basis
                    },
                ),
            ] {
                assert!(
                    !publication.basis_is_current(&state, &writer, &changed),
                    "{guard}"
                );
            }
            let root = publication.root.epoch();
            root.store(writer.epoch + 2, Ordering::Release);
            assert!(
                !publication.basis_is_current(&state, &writer, &basis),
                "current closed epoch"
            );
            root.store(writer.epoch, Ordering::Release);
            state.writers.count += 1;
            assert!(
                !publication.basis_is_current(&state, &writer, &basis),
                "overlapping writer"
            );
            state.writers.count -= 1;
            state.plan.as_mut().unwrap().policy_fingerprint = [4; 32];
            assert!(
                !publication.basis_is_current(&state, &writer, &basis),
                "installed plan fingerprint"
            );
            state.plan.as_mut().unwrap().policy_fingerprint = basis.fingerprint;
            state.scopes.get_mut(&basis.fact_scope).unwrap().fingerprint = [4; 32];
            assert!(
                !publication.basis_is_current(&state, &writer, &basis),
                "installed scope fingerprint"
            );
            state.scopes.get_mut(&basis.fact_scope).unwrap().fingerprint = basis.fingerprint;
            let expired = NativeCaptureBasis {
                fact_horizon: Some(tokio::time::Instant::now()),
                ..basis
            };
            state.scopes.get_mut(&basis.fact_scope).unwrap().facts[0].3 = expired.fact_horizon;
            assert!(
                !publication.basis_is_current(&state, &writer, &expired),
                "expiry with matching installed identity"
            );
            state.scopes.get_mut(&basis.fact_scope).unwrap().facts[0].3 = basis.fact_horizon;
            assert!(publication.basis_is_current(&state, &writer, &basis));
        }
        writer.commit();
        let authority = CaptureAuthority {
            namespace_cookie: basis.identity.key.namespace_cookie,
            attachment_generation: 13,
            scope: basis.identity.scope,
            ifindex: 2,
            ..Default::default()
        };
        let original = NativeBasis {
            capture: basis,
            producer: basis.producer,
            authority,
            ingress: honk_datapath::forward::Ingress {
                scope: basis.fact_scope,
                namespace: authority.namespace_cookie,
                ifindex: authority.ifindex,
                attachment: authority.attachment_generation,
                mark: honk_datapath::forward::MarkProvenance::BeforeSkb,
            },
            realm_index: 0,
            rx_queue: 0,
            extent: OriginalExtent {
                frame_length: 64,
                l3_offset: 14,
                l3_length: 50,
                vlan_tci: [0; 2],
                vlan_proto: [0; 2],
                vlan_count: 0,
                inline_vlan_count: 0,
                dscp: 0,
            },
        };
        let cell = stale_only_captured_cell(&publication);
        let before = publication.selection_epoch().unwrap();
        let error = publication
            .prepare_original(&cell, &original)
            .err()
            .expect("stale prepare must retry before consulting map/loader");
        assert_eq!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::WouldBlock)
        );
        assert_eq!(publication.selection_epoch(), Some(before + 2));
        assert!(!publication.state.lock().writers.failed);
        assert_eq!(cell.0.phase().load(Ordering::Acquire), NATIVE_OP_IDLE);
        for (producer, installed, now, expected) in [
            (100, 200, 99, Some(100)),
            (200, 100, 99, Some(100)),
            (100, u64::MAX, 99, Some(100)),
            (100, 200, 100, None),
            (200, 100, 100, None),
            (100, 200, 101, None),
            (0, 200, 0, None),
            (200, 0, 0, None),
        ] {
            assert_eq!(
                original_horizon(producer, installed, now),
                expected,
                "producer={producer}, installed={installed}, now={now}"
            );
        }
    }

    #[test]
    fn native_import_lookup_failure_defers_grace_until_owner_turn() {
        use super::*;
        let publication = recorded_publication();
        publication.write(NativeReason::Startup).unwrap().commit();
        let open = publication.selection_epoch().unwrap();
        let observed = publication
            .test_grace_observed_epoch
            .load(Ordering::Acquire);
        assert_eq!(publication.import_lookup_result(Ok(17)).unwrap(), 17);
        assert_eq!(publication.selection_epoch(), Some(open));
        assert!(!publication.import_failed.load(Ordering::Acquire));
        let lock = publication.state.lock();
        let error = publication
            .import_lookup_result::<()>(Err(io::Error::from_raw_os_error(libc::EIO)))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(publication.root.epoch().load(Ordering::Acquire), open + 1);
        assert!(publication.import_failed.load(Ordering::Acquire));
        assert!(publication.import_close_pending.load(Ordering::Acquire));
        assert_eq!(
            publication
                .test_grace_observed_epoch
                .load(Ordering::Acquire),
            observed
        );
        assert!(!lock.writers.failed);
        drop(lock);
        assert!(publication.selection_epoch().is_none());
        publication.finish_import_turn().unwrap();
        assert!(!publication.import_close_pending.load(Ordering::Acquire));
        assert!(
            publication
                .test_grace_observed_epoch
                .load(Ordering::Acquire)
                > observed
        );
        let state = publication.state.lock();
        assert!(state.writers.failed);
        assert!(!state.ready && !state.capture_ready);
        drop(state);
        assert!(publication.write(NativeReason::RuntimeMaintenance).is_err());
        let drained = publication
            .recording_events_for_test()
            .iter()
            .filter(|event| event.kind == NATIVE_EVENT_CLOSE_DRAINED)
            .count();
        publication.finish_import_turn().unwrap();
        assert_eq!(
            publication
                .recording_events_for_test()
                .iter()
                .filter(|event| event.kind == NATIVE_EVENT_CLOSE_DRAINED)
                .count(),
            drained
        );
    }

    #[test]
    fn native_claim_resident_and_scan_charges_precede_kernel_syscalls() {
        use super::*;
        assert_eq!(size_of::<NativeKey>(), 56);
        assert_eq!(size_of::<NativeClaim>(), 72);
        assert_eq!(size_of::<(NativeKey, NativeClaim)>(), 128);
        let count = 1024_u32;
        let resident = size_of::<NativeKey>()
            .checked_add(size_of::<NativeClaim>())
            .unwrap()
            .checked_add(128)
            .unwrap()
            .checked_mul(count as usize)
            .unwrap()
            .checked_add(2 * PAGE_BYTES)
            .unwrap();
        assert_eq!(resident, 256 * count as usize + 2 * PAGE_BYTES);
        let budget = MemoryBudget::new(resident - 1);
        let error = Map::new(
            &budget,
            1,
            size_of::<NativeKey>(),
            size_of::<NativeClaim>(),
            count,
            0,
        )
        .err()
        .expect("one-byte resident deficit must fail before BPF_MAP_CREATE");
        assert_eq!(error.to_string(), "native shared memory budget exhausted");
        assert_eq!(budget.used(), 0);
        let error = Map::new(&budget, 1, usize::MAX, 72, 1, 0).err().unwrap();
        assert_eq!(error.to_string(), "native map charge overflow");
        let publication = recorded_publication();
        let scan = (publication.capacity as usize)
            .checked_mul(size_of::<(NativeKey, NativeClaim)>())
            .unwrap()
            .checked_add(4 * PAGE_BYTES)
            .unwrap();
        assert_eq!(scan, 128 * publication.capacity as usize + 4 * PAGE_BYTES);
        let used = publication.budget.used();
        let pressure = publication
            .budget
            .reserve((2 << 20) - used - (scan - 1))
            .unwrap();
        let before = publication.budget.used();
        let error = publication
            .scan_claims()
            .err()
            .expect("one-byte scan deficit must fail before BPF_MAP_GET_NEXT_KEY");
        assert_eq!(error.to_string(), "native shared memory budget exhausted");
        assert_eq!(publication.budget.used(), before);
        assert!(!publication.state.lock().writers.failed);
        drop(pressure);
    }

    fn recorded_publication() -> std::sync::Arc<super::NativePublication> {
        super::NativePublication::recording_for_test(honk_netstack::MemoryBudget::new(2 << 20))
            .unwrap()
    }

    #[test]
    fn final_topology_binding_serializes_dns_publication_and_terminal_close() {
        use super::*;
        use std::sync::{Barrier, mpsc};
        for close in [false, true] {
            let publication = recorded_publication();
            let subscribed = Arc::new(Barrier::new(2));
            let bound = Arc::new(Barrier::new(2));
            let events = Arc::new(std::sync::Mutex::new(Vec::new()));
            let owner = publication.clone();
            let first = subscribed.clone();
            let second = bound.clone();
            let recorded = events.clone();
            let admission = std::thread::spawn(move || {
                owner
                    .admit_topology_with(|_| {
                        recorded.lock().unwrap().push("subscribed");
                        first.wait();
                        second.wait();
                        recorded.lock().unwrap().extend(["bind-first", "bind-last"]);
                        Ok(())
                    })
                    .unwrap();
            });
            subscribed.wait();
            let (started_tx, started_rx) = mpsc::channel();
            let owner = publication.clone();
            let recorded = events.clone();
            let mutation = std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                if close {
                    owner.quiesce(NativeReason::Shutdown).unwrap();
                } else {
                    let writer = owner.write(NativeReason::ScopedDns).unwrap();
                    writer.commit();
                }
                recorded.lock().unwrap().push("mutation");
            });
            started_rx.recv().unwrap();
            assert!(publication.state.try_lock().is_none());
            assert_eq!(*events.lock().unwrap(), ["subscribed"]);
            bound.wait();
            admission.join().unwrap();
            mutation.join().unwrap();
            assert_eq!(
                *events.lock().unwrap(),
                ["subscribed", "bind-first", "bind-last", "mutation"]
            );
        }
    }

    #[test]
    fn final_topology_partial_binding_failure_permanently_refuses_readiness() {
        use super::*;
        let publication = recorded_publication();
        let mut bound = Vec::new();
        let result = publication.admit_topology_with(|_| {
            bound.push(1);
            Err::<(), _>(io::Error::new(
                io::ErrorKind::InvalidData,
                "second binding failed",
            ))
        });
        assert!(result.is_err());
        assert_eq!(bound, [1]);
        let state = publication.state.lock();
        assert!(state.writers.failed);
        assert!(!state.ready && !state.capture_ready);
        drop(state);
        assert_eq!(publication.root.epoch().load(Ordering::SeqCst) & 1, 0);
        assert!(publication.set_ready(true).is_err());
        assert!(publication.set_capture_ready(true).is_err());
        assert!(publication.write(NativeReason::ScopedDns).is_err());
        assert!(publication.admit_topology_with(|_| Ok(())).is_err());
    }

    #[test]
    fn real_writer_frontiers_preserve_overlap_grace_and_last_commit() {
        use super::*;
        let publication = recorded_publication();
        let first = publication.write(NativeReason::Policy).unwrap();
        assert_eq!(
            publication.test_grace_observed_epoch.load(Ordering::SeqCst),
            2
        );
        let second = publication.write(NativeReason::RuntimeMaintenance).unwrap();
        assert_eq!(
            publication.test_grace_observed_epoch.load(Ordering::SeqCst),
            4
        );
        assert_eq!(publication.root.epoch().load(Ordering::SeqCst), 4);
        first.commit();
        assert_eq!(publication.root.epoch().load(Ordering::SeqCst), 4);
        second.commit();
        assert_eq!(publication.root.epoch().load(Ordering::SeqCst), 5);
        let events = publication.recording_events_for_test();
        let stores: Vec<_> = events
            .iter()
            .filter(|e| e.kind == NATIVE_EVENT_CLOSE_STORED)
            .collect();
        assert_eq!(
            stores
                .iter()
                .map(|e| (e.epoch_before, e.epoch_after))
                .collect::<Vec<_>>(),
            [(0, 2), (2, 4)]
        );
        for store in stores {
            assert_eq!(
                store.flags & NATIVE_EVENT_FLAG_TIMESTAMP_VALID,
                NATIVE_EVENT_FLAG_TIMESTAMP_VALID
            );
            assert!(store.boottime_before_ns <= store.boottime_after_ns);
            let drained = events
                .iter()
                .find(|event| {
                    event.kind == NATIVE_EVENT_CLOSE_DRAINED
                        && event.operation_id == store.operation_id
                })
                .unwrap();
            assert!(drained.seq > store.seq);
            assert_eq!(drained.related_seq, store.seq);
            assert!(drained.boottime_after_ns >= store.boottime_after_ns);
        }
        let outcomes: Vec<_> = events
            .iter()
            .filter(|e| e.kind == NATIVE_EVENT_WRITER_OUTCOME)
            .collect();
        assert_eq!(outcomes.len(), 2);
        assert!(
            outcomes
                .iter()
                .all(|e| e.outcome == NATIVE_OUTCOME_COMMITTED)
        );
        let reopen: Vec<_> = events
            .iter()
            .filter(|e| e.kind == NATIVE_EVENT_REOPEN_STORED)
            .collect();
        assert_eq!(reopen.len(), 1);
        assert_eq!((reopen[0].epoch_before, reopen[0].epoch_after), (4, 5));
        assert_eq!(reopen[0].writer_id, outcomes[1].writer_id);
        assert_eq!(reopen[0].reason, NativeReason::RuntimeMaintenance as u32);
    }

    #[test]
    fn held_writer_reopens_after_more_than_4096_overlapping_milestones() {
        use super::*;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page > 0);
        let bytes = Recording::test_replacement_peak_bytes()
            .unwrap()
            .checked_add(4 * PAGE_BYTES)
            .and_then(|bytes| bytes.checked_add(page as usize))
            .unwrap();
        let budget = MemoryBudget::new(bytes);
        let publication = NativePublication::recording_for_test(budget.clone()).unwrap();
        publication.state.lock().recording = Recording::new(&budget, 1).unwrap();
        let directory = tempfile::tempdir().unwrap();
        publication.initialize_export(directory.path()).unwrap();
        let held = publication.write(NativeReason::Reload).unwrap();
        let held_id = held.writer_id;
        for _ in 0..1024 {
            publication
                .write(NativeReason::RuntimeMaintenance)
                .unwrap()
                .commit();
        }
        assert!(
            publication
                .state
                .lock()
                .recording
                .is_live_writer(held_id, held.operation_id)
        );
        held.commit();
        assert_eq!(publication.epoch_for_test() & 1, 1);
        assert!(!publication.state.lock().recording.recording_error);
        assert!(!publication.state.lock().writers.failed);
        let result = publication.export_recording(false, false);
        assert!(result.error.is_none());
        let artifact: serde_json::Value =
            serde_json::from_slice(&std::fs::read(result.path.unwrap()).unwrap()).unwrap();
        assert!(
            artifact["total_appended"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 4096
        );
        assert!(
            artifact["overwritten_events"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert!(
            artifact["first_retained_seq"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 1
        );
        assert_eq!(artifact["recording_error"], false);
        assert_eq!(artifact["complete"], false);
        assert!(
            artifact["incomplete_reasons"]
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::from("HISTORY_OVERWRITTEN"))
        );
    }

    #[test]
    fn independent_dns_writer_owns_participant_and_replacement_during_maintenance() {
        use super::*;
        let publication = recorded_publication();
        publication
            .state
            .lock()
            .recording
            .register_hook(HookIdentity {
                hook_id: 1,
                target_serial: 1,
                kind: 0,
                scope: 1,
                namespace_cookie: 1,
                ifindex: 1,
                attachment_generation: 1,
                counter_map_id: 1,
                program_id: 0,
            })
            .unwrap();
        let maintenance = publication.write(NativeReason::RuntimeMaintenance).unwrap();
        let dns = publication.write(NativeReason::ScopedDns).unwrap();
        let dns_id = dns.writer_id;
        publication
            .change(&dns, NativeReason::ScopedDns, |state| {
                let (operation_id, writer_id, reason) = state.operation_context;
                assert_eq!(writer_id, dns_id);
                assert_ne!(writer_id, maintenance.writer_id);
                state.recording.program_replacement(
                    1,
                    0,
                    19,
                    NATIVE_OUTCOME_PENDING,
                    reason,
                    operation_id,
                    writer_id,
                )?;
                state.recording.program_replacement(
                    1,
                    0,
                    19,
                    NATIVE_OUTCOME_COMMITTED,
                    reason,
                    operation_id,
                    writer_id,
                )?;
                Ok(())
            })
            .unwrap();
        let events = publication.recording_events_for_test();
        assert!(events.len() < 32);
        assert_eq!(events.first().unwrap().seq, 1);
        let replacements: Vec<_> = events
            .iter()
            .filter(|event| event.kind == NATIVE_EVENT_PROGRAM_REPLACED)
            .collect();
        assert_eq!(replacements.len(), 2);
        for event in replacements {
            assert_eq!(event.writer_id, dns_id);
            let begin = events
                .iter()
                .find(|begin| {
                    begin.kind == NATIVE_EVENT_WRITER_BEGIN
                        && begin.operation_id == event.operation_id
                })
                .unwrap();
            assert_eq!(begin.writer_id, dns_id);
            assert_eq!(begin.reason, NativeReason::ScopedDns as u32);
        }
        dns.commit();
        assert_eq!(publication.epoch_for_test() & 1, 0);
        maintenance.commit();
        assert_eq!(publication.epoch_for_test() & 1, 1);
    }

    #[test]
    fn participant_requires_guard_from_the_same_publication_and_live_root_operation() {
        use super::*;
        let publication = recorded_publication();
        let other = recorded_publication();
        let writer = other.write(NativeReason::ScopedDns).unwrap();
        assert!(
            publication
                .change(&writer, NativeReason::ScopedDns, |_| Ok(()))
                .is_err()
        );
        writer.commit();
        let mut writer = publication.write(NativeReason::ScopedDns).unwrap();
        let root_operation = writer.operation_id;
        writer.operation_id = root_operation + 1;
        assert!(
            publication
                .change(&writer, NativeReason::ScopedDns, |_| Ok(()))
                .is_err()
        );
        writer.operation_id = root_operation;
        writer.commit();
        assert!(!publication.state.lock().writers.failed);
    }

    #[test]
    fn participants_follow_live_sibling_after_first_writer_settles() {
        use super::*;
        let publication = recorded_publication();
        let first = publication.write(NativeReason::Reload).unwrap();
        let second = publication.write(NativeReason::RuntimeMaintenance).unwrap();
        let departed = first.writer_id;
        let surviving = second.writer_id;
        first.commit();
        assert!(
            publication
                .state
                .lock()
                .recording
                .is_live_writer(surviving, second.operation_id)
        );
        publication
            .change(&second, NativeReason::Policy, |state| {
                assert_eq!(state.operation_context.1, surviving);
                Ok(())
            })
            .unwrap();
        publication
            .change(&second, NativeReason::ScopedDns, |state| {
                assert_eq!(state.operation_context.1, surviving);
                Ok(())
            })
            .unwrap();
        let events = publication.recording_events_for_test();
        assert!(events.len() < 32);
        assert_eq!(events.first().unwrap().seq, 1);
        for reason in [NativeReason::Policy, NativeReason::ScopedDns] {
            let participant: Vec<_> = events
                .iter()
                .filter(|event| {
                    event.reason == reason as u32
                        && matches!(
                            event.kind,
                            NATIVE_EVENT_WRITER_BEGIN | NATIVE_EVENT_WRITER_OUTCOME
                        )
                })
                .collect();
            assert_eq!(participant.len(), 2);
            assert!(
                participant
                    .iter()
                    .all(|event| event.writer_id == surviving && event.writer_id != departed)
            );
            assert_eq!(participant[0].operation_id, participant[1].operation_id);
        }
        second.commit();
        assert!(
            !publication
                .state
                .lock()
                .recording
                .is_live_writer(surviving, 2)
        );
        assert_eq!(publication.epoch_for_test(), 5);
    }

    #[test]
    fn real_writer_failures_and_participants_never_invent_reopen() {
        use super::*;
        let publication = recorded_publication();
        let first = publication.write(NativeReason::Reload).unwrap();
        let second = publication.write(NativeReason::Mode).unwrap();
        let participant: anyhow::Result<()> =
            publication.change(&first, NativeReason::ScopedDns, |_| {
                anyhow::bail!("participant failed")
            });
        assert!(participant.is_err());
        first.commit();
        drop(second);
        let events = publication.recording_events_for_test();
        let dns: Vec<_> = events
            .iter()
            .filter(|e| e.reason == NativeReason::ScopedDns as u32)
            .collect();
        assert_eq!(dns.len(), 2);
        assert_eq!(
            dns[0].writer_id,
            events
                .iter()
                .find(|e| e.kind == NATIVE_EVENT_WRITER_BEGIN)
                .unwrap()
                .writer_id
        );
        assert_eq!(dns[0].operation_id, dns[1].operation_id);
        assert_eq!(dns[1].outcome, NATIVE_OUTCOME_FAILED);
        assert!(!events.iter().any(|e| e.kind == NATIVE_EVENT_REOPEN_STORED));
        assert_eq!(
            events
                .iter()
                .filter(|e| e.kind == NATIVE_EVENT_WRITER_OUTCOME)
                .count(),
            3
        );
    }

    #[test]
    fn committed_unready_writer_records_deferral_without_reopen() {
        use super::*;
        let publication = recorded_publication();
        {
            let mut state = publication.state.lock();
            state.ready = false;
            state.test_can_open = false;
        }
        publication.write(NativeReason::Ready).unwrap().commit();
        let events = publication.recording_events_for_test();
        let outcome = events
            .iter()
            .find(|e| e.kind == NATIVE_EVENT_WRITER_OUTCOME)
            .unwrap();
        assert_eq!(outcome.outcome, NATIVE_OUTCOME_COMMITTED);
        assert_eq!(outcome.flags, NATIVE_EVENT_FLAG_NOT_READY);
        assert!(!events.iter().any(|e| e.kind == NATIVE_EVENT_REOPEN_STORED));
    }

    #[test]
    fn failed_grace_has_store_and_failed_outcome_without_drained_marker() {
        use super::*;
        let publication = recorded_publication();
        publication.set_grace_failure_for_test(true);
        assert!(publication.write(NativeReason::RuntimeMaintenance).is_err());
        let events = publication.recording_events_for_test();
        assert!(events.iter().any(|e| e.kind == NATIVE_EVENT_CLOSE_STORED));
        assert!(!events.iter().any(|e| e.kind == NATIVE_EVENT_CLOSE_DRAINED));
        assert!(
            events.iter().any(
                |e| e.kind == NATIVE_EVENT_WRITER_OUTCOME && e.outcome == NATIVE_OUTCOME_FAILED
            )
        );
        assert_eq!(publication.root.epoch().load(Ordering::SeqCst), 2);
    }

    #[test]
    fn map_failure_repeated_quiesce_and_exhaustion_use_recorded_frontier() {
        use super::*;
        let publication = recorded_publication();
        publication.write(NativeReason::Policy).unwrap().commit();
        assert!(publication.maintenance_needed(|_, _| false).is_err());
        publication.quiesce(NativeReason::Shutdown).unwrap();
        publication.quiesce(NativeReason::Shutdown).unwrap();
        let events = publication.recording_events_for_test();
        assert!(events.iter().any(|e| e.kind == NATIVE_EVENT_CLOSE_STORED
            && e.reason == NativeReason::MapReadFailure as u32));
        assert_eq!(
            events
                .iter()
                .filter(|e| e.kind == NATIVE_EVENT_TERMINAL_STATE
                    && e.reason == NativeReason::Shutdown as u32)
                .count(),
            2
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.kind == NATIVE_EVENT_CLOSE_STORED)
                .count(),
            2
        );
        let exhausted = recorded_publication();
        exhausted.root.epoch().store(u64::MAX - 1, Ordering::SeqCst);
        assert!(exhausted.write(NativeReason::Policy).is_err());
        assert!(
            exhausted
                .recording_events_for_test()
                .iter()
                .any(|e| e.reason == NativeReason::EpochExhaustion as u32)
        );
        assert_eq!(exhausted.root.epoch().load(Ordering::SeqCst), u64::MAX - 1);
    }

    fn counter_fixture(
        budget: &std::sync::Arc<honk_netstack::MemoryBudget>,
    ) -> super::ClosedCounters {
        use super::*;
        ClosedCounters {
            map: Map {
                fd: std::fs::File::open("/dev/null").unwrap().into(),
                _memory: Vec::new(),
            },
            generations: [CounterGeneration::default(); 256],
            _identity_memory: reserve(budget, 8192 + 513 * size_of::<NativeClosedCounterV1>())
                .unwrap(),
            test_cells: Some(Box::new([NativeClosedCounterV1::default(); 513])),
        }
    }

    #[test]
    fn clock_failure_keeps_required_safety_store_and_refuses_later_reopen() {
        use super::*;
        let publication = recorded_publication();
        publication.write(NativeReason::Policy).unwrap().commit();
        publication.state.lock().recording.fail_clock_for_test(true);
        assert!(publication.write(NativeReason::RuntimeMaintenance).is_err());
        assert_eq!(publication.epoch_for_test(), 4);
        let events = publication.recording_events_for_test();
        let store = events
            .iter()
            .find(|event| {
                event.kind == NATIVE_EVENT_CLOSE_STORED
                    && event.reason == NativeReason::RuntimeMaintenance as u32
            })
            .unwrap();
        assert_eq!((store.epoch_before, store.epoch_after), (3, 4));
        assert_eq!((store.boottime_before_ns, store.boottime_after_ns), (0, 0));
        assert_eq!(store.flags & NATIVE_EVENT_FLAG_TIMESTAMP_VALID, 0);
        assert_eq!(store.outcome, NATIVE_OUTCOME_FAILED);
        assert!(publication.state.lock().recording.clock_error);
        publication
            .state
            .lock()
            .recording
            .fail_clock_for_test(false);
        assert!(publication.write(NativeReason::Policy).is_err());
        assert!(
            !publication
                .recording_events_for_test()
                .iter()
                .any(|event| event.kind == NATIVE_EVENT_REOPEN_STORED && event.epoch_after > 3)
        );
    }

    #[test]
    fn tagged_counts_seal_only_old_epochs_and_refuse_live_slot_reuse() {
        use super::*;
        let budget = MemoryBudget::new(2 << 20);
        let mut counters = counter_fixture(&budget);
        let mut recording = Recording::test_new(&budget).unwrap();
        for hook in 0..2u64 {
            recording
                .register_hook(HookIdentity {
                    hook_id: hook + 1,
                    target_serial: 1,
                    kind: hook as u32,
                    scope: 1,
                    namespace_cookie: 1,
                    ifindex: 1,
                    attachment_generation: 1,
                    counter_map_id: 1,
                    program_id: 0,
                })
                .unwrap();
        }
        for _ in 0..4 {
            recording.operation();
        }
        counters.prepare(0, 1, 1).unwrap();
        counters
            .insert_cell(
                0,
                NativeClosedCounterV1 {
                    epoch: 0,
                    ordinary_drops: 9,
                    ..Default::default()
                },
            )
            .unwrap();
        counters.seal(Some(0), [1, 2], &mut recording).unwrap();
        assert!(counters.generations[0].live);
        assert!(
            !recording
                .events()
                .any(|e| e.kind == NATIVE_EVENT_CLOSED_COUNTS_FINAL)
        );
        assert!(counters.prepare(512, 2, 2).is_err());
        assert_eq!(counters.cell(0).unwrap().ordinary_drops, 9);
        counters.prepare(2, 3, 3).unwrap();
        counters
            .insert_cell(
                0,
                NativeClosedCounterV1 {
                    epoch: 0,
                    ordinary_drops: 10,
                    ..Default::default()
                },
            )
            .unwrap();
        counters.seal(Some(2), [1, 2], &mut recording).unwrap();
        let final_zero: Vec<_> = recording
            .events()
            .filter(|e| e.kind == NATIVE_EVENT_CLOSED_COUNTS_FINAL && e.counter_epoch == 0)
            .collect();
        assert_eq!(final_zero.len(), 2);
        assert_eq!(
            (final_zero[0].hook_id, final_zero[0].counter_value),
            (1, 10)
        );
        assert_eq!((final_zero[1].hook_id, final_zero[1].counter_value), (2, 0));
        assert!(counters.generations[1].live);
        assert!(!counters.generations[0].live);
        counters.prepare(512, 4, 4).unwrap();
        assert_eq!(counters.cell(0).unwrap().epoch, 512);
        assert_eq!(counters.cell(0).unwrap().ordinary_drops, 0);
        counters.seal(None, [1, 2], &mut recording).unwrap();
        assert!(
            counters
                .generations
                .iter()
                .all(|generation| !generation.live)
        );
    }

    #[test]
    fn invalid_tags_and_overflow_cannot_be_complete_counter_evidence() {
        use super::*;
        let budget = MemoryBudget::new(2 << 20);
        let mut counters = counter_fixture(&budget);
        let mut recording = Recording::test_new(&budget).unwrap();
        for hook in 0..2u64 {
            recording
                .register_hook(HookIdentity {
                    hook_id: hook + 1,
                    target_serial: 1,
                    kind: hook as u32,
                    scope: 1,
                    namespace_cookie: 1,
                    ifindex: 1,
                    attachment_generation: 1,
                    counter_map_id: 1,
                    program_id: 0,
                })
                .unwrap();
        }
        recording.operation();
        counters.prepare(2, 1, 1).unwrap();
        counters
            .insert_cell(
                2,
                NativeClosedCounterV1 {
                    epoch: 4,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(counters.seal(None, [1, 2], &mut recording).is_err());
        assert!(counters.generations[1].live);
        counters
            .insert_cell(
                2,
                NativeClosedCounterV1 {
                    epoch: 2,
                    overflow: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        counters.seal(None, [1, 2], &mut recording).unwrap();
        assert!(recording.counter_overflow);
        assert!(
            recording
                .events()
                .any(|e| e.kind == NATIVE_EVENT_CLOSED_COUNTS_FINAL
                    && e.flags & NATIVE_EVENT_FLAG_COUNTER_OVERFLOW != 0)
        );
        counters
            .insert_cell(
                512,
                NativeClosedCounterV1 {
                    overflow: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(counters.seal(None, [1, 2], &mut recording).is_err());
    }

    #[test]
    fn recording_and_target_reservations_fail_before_kernel_creation() {
        use super::*;
        let error = NativePublication::new_with_capacity(MemoryBudget::new(598_015), 1)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "native shared memory budget exhausted");
        let error = ClosedCounters::new(&MemoryBudget::new(100_515))
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "native shared memory budget exhausted");
    }

    #[test]
    fn actual_owner_drop_exports_recorded_partial_terminal_closure() {
        use super::*;
        let directory = tempfile::tempdir().unwrap();
        let publication = recorded_publication();
        let path = publication.initialize_export(directory.path()).unwrap();
        publication.write(NativeReason::Policy).unwrap().commit();
        drop(publication);
        let artifact: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(artifact["final"], false);
        assert_eq!(artifact["complete"], false);
        let events = artifact["events"].as_array().unwrap();
        assert!(
            events
                .iter()
                .any(|event| event["kind"] == NATIVE_EVENT_CLOSE_STORED
                    && event["reason"] == NativeReason::OwnerDrop as u32
                    && event["epoch_before"] == "3"
                    && event["epoch_after"] == "4")
        );
        assert!(
            events
                .iter()
                .any(|event| event["kind"] == NATIVE_EVENT_TERMINAL_STATE
                    && event["reason"] == NativeReason::OwnerDrop as u32)
        );
        assert!(
            !events
                .iter()
                .any(|event| event["kind"] == NATIVE_EVENT_COLLECTION_END)
        );
    }

    #[test]
    fn failed_hook_withdrawal_still_joins_readers_without_finalization() {
        use super::*;
        for fail_grace in [false, true] {
            let publication = recorded_publication();
            publication.quiesce(NativeReason::Shutdown).unwrap();
            let before = publication.recording_events_for_test().len();
            publication.set_grace_failure_for_test(fail_grace);
            publication
                .test_grace_observed_epoch
                .store(u64::MAX, Ordering::SeqCst);
            assert!(publication.finalize_recording(false).is_err());
            assert_eq!(
                publication.test_grace_observed_epoch.load(Ordering::SeqCst),
                publication.root.epoch().load(Ordering::SeqCst)
            );
            let events = publication.recording_events_for_test();
            let events = &events[before..];
            assert_eq!(
                events.last().unwrap().kind,
                if fail_grace {
                    NATIVE_EVENT_TERMINAL_STATE
                } else {
                    NATIVE_EVENT_CLOSE_DRAINED
                }
            );
            assert!(!events.iter().any(|event| matches!(
                event.kind,
                NATIVE_EVENT_CLOSED_COUNTS_FINAL | NATIVE_EVENT_COLLECTION_END
            )));
            {
                let state = publication.state.lock();
                assert!(state.writers.failed);
                assert!(!state.recording.hooks_joined);
                assert!(!state.recording.completed);
            }
            publication.set_grace_failure_for_test(false);
            assert!(publication.finalize_recording(true).is_err());
            let state = publication.state.lock();
            assert!(!state.recording.hooks_joined && !state.recording.completed);
        }
    }

    #[test]
    fn recording_finalization_rejects_unclosed_writers_before_reader_grace() {
        use super::*;
        let publication = recorded_publication();
        let writer = publication.write(NativeReason::Policy).unwrap();
        publication.quiesce(NativeReason::Shutdown).unwrap();
        publication
            .test_grace_observed_epoch
            .store(u64::MAX, Ordering::SeqCst);
        assert!(publication.finalize_recording(false).is_err());
        assert_eq!(
            publication.test_grace_observed_epoch.load(Ordering::SeqCst),
            u64::MAX
        );
        {
            let state = publication.state.lock();
            assert!(state.writers.failed);
            assert!(!state.recording.hooks_joined && !state.recording.completed);
        }
        writer.commit();
        assert!(publication.finalize_recording(true).is_err());
    }

    #[test]
    fn terminal_finalization_exports_before_charge_release_and_drop_has_no_later_store() {
        use super::*;
        let directory = tempfile::tempdir().unwrap();
        let budget = MemoryBudget::new(2 << 20);
        let publication = NativePublication::recording_for_test(budget.clone()).unwrap();
        let path = publication.initialize_export(directory.path()).unwrap();
        publication.write(NativeReason::Policy).unwrap().commit();
        publication.quiesce(NativeReason::Shutdown).unwrap();
        publication.finalize_recording(true).unwrap();
        let charged = budget.used();
        let result = publication.export_recording(true, true);
        assert_eq!(
            result.status,
            NativeExportPublicationResult::PublishedDurable
        );
        assert!(result.error.is_none());
        assert_eq!(budget.used(), charged);
        let before = std::fs::read(&path).unwrap();
        let events = publication.recording_events_for_test();
        assert_eq!(events.last().unwrap().kind, NATIVE_EVENT_COLLECTION_END);
        let artifact: serde_json::Value = serde_json::from_slice(&before).unwrap();
        assert_eq!(artifact["final"], true);
        assert_eq!(artifact["complete"], false);
        drop(publication);
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert_eq!(budget.used(), 0);
    }

    fn charged_map(
        budget: &std::sync::Arc<honk_netstack::MemoryBudget>,
        bytes: usize,
    ) -> super::Map {
        super::Map {
            fd: std::fs::File::open("/dev/null").unwrap().into(),
            _memory: vec![super::reserve(budget, bytes).unwrap()],
        }
    }

    fn charged_resources(
        budget: &std::sync::Arc<honk_netstack::MemoryBudget>,
        facts: std::sync::Arc<super::Facts>,
    ) -> super::CandidateResources {
        super::CandidateResources {
            facts,
            domain: charged_map(budget, 20),
            memory: super::reserve(budget, 30).unwrap(),
        }
    }

    #[test]
    fn retired_resources_close_fds_without_refunding_shared_facts_or_programs() {
        use super::*;
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        let budget = MemoryBudget::new(150);
        let observed_map = |bytes| {
            let (fd, peer) = UnixStream::pair().unwrap();
            peer.set_nonblocking(true).unwrap();
            (
                Map {
                    fd: fd.into(),
                    _memory: vec![reserve(&budget, bytes).unwrap()],
                },
                peer,
            )
        };
        let mut peers = Vec::new();
        let facts = Arc::new(Facts {
            maps: std::array::from_fn(|_| {
                let (map, peer) = observed_map(10);
                peers.push(peer);
                map
            }),
        });
        let (domain, mut first_peer) = observed_map(20);
        let first = CandidateResources {
            facts: facts.clone(),
            domain,
            memory: reserve(&budget, 30).unwrap(),
        };
        let (domain, mut second_peer) = observed_map(20);
        let second = CandidateResources {
            facts,
            domain,
            memory: reserve(&budget, 30).unwrap(),
        };
        let mut memory = Vec::new();

        first.retire(&mut memory);
        assert_eq!(budget.used(), 150);
        assert_eq!(memory.len(), 2);
        assert_eq!(first_peer.read(&mut [0]).unwrap(), 0);
        for peer in &mut peers {
            assert_eq!(
                peer.read(&mut [0]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }

        second.retire(&mut memory);
        assert_eq!(budget.used(), 150);
        assert_eq!(memory.len(), 9);
        assert_eq!(second_peer.read(&mut [0]).unwrap(), 0);
        for peer in &mut peers {
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
        assert!(reserve(&budget, 1).is_err());
        drop(memory);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn next_successful_retirement_preserves_the_previous_charge() {
        use super::*;
        let budget = MemoryBudget::new(2 << 20);
        let publication = NativePublication::closed_for_test(budget.clone()).unwrap();
        let baseline = budget.used();
        let facts = Arc::new(Facts {
            maps: std::array::from_fn(|_| charged_map(&budget, 10)),
        });
        let resources = charged_resources(&budget, facts);
        let mut state = publication.state.lock();
        resources.retire(&mut state.retired_memory);
        assert_eq!(budget.used(), baseline + 100);
        state.finish_retirement();
        assert_eq!(budget.used(), baseline + 100);
        assert!(!state.retired_memory.is_empty());
        drop(state);
        drop(publication);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn retained_generation_exhaustion_fails_closed_and_drop_refunds_it() {
        use super::*;
        let budget = MemoryBudget::new(2 << 20);
        let publication = NativePublication::closed_for_test(budget.clone()).unwrap();
        let used_before_resources = budget.used();
        let facts = Arc::new(Facts {
            maps: std::array::from_fn(|_| charged_map(&budget, 10)),
        });
        let resources = charged_resources(&budget, facts);
        {
            let mut state = publication.state.lock();
            resources.retire(&mut state.retired_memory);
            assert_eq!(
                budget.used() - used_before_resources,
                100,
                "retired facts maps and domain must keep their charge"
            );
            state.writers = Writers::default();
            state.writers.begin().unwrap();
            let writer_id = state.recording.writer();
            let operation_id = state.recording.operation();
            state.recording.append(NativePublicationEventV1 {
                writer_id,
                operation_id,
                reason: NativeReason::Policy as u32,
                kind: NATIVE_EVENT_WRITER_BEGIN,
                ..Default::default()
            });
        }
        let writer = NativeWrite {
            publication: publication.clone(),
            epoch: 2,
            committed: false,
            writer_id: 1,
            operation_id: 1,
            reason: NativeReason::Policy,
            host_preparation: None,
        };
        let charged = budget.used();
        let error = publication
            .change(&writer, NativeReason::Policy, |_| {
                // One byte past the limit only while every retired map keeps its charge.
                reserve(&budget, budget.limit() - charged + 1)
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "native shared memory budget exhausted");
        assert_eq!(budget.used(), charged);
        {
            let state = publication.state.lock();
            assert!(state.writers.failed);
            assert!(!state.retired_memory.is_empty());
            assert_eq!(publication.root.epoch().load(Ordering::SeqCst) & 1, 0);
        }
        drop(writer);
        assert_eq!(publication.state.lock().writers.count, 0);
        assert!(publication.write(NativeReason::Policy).is_err());
        drop(publication);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn unchanged_scope_identity_still_compares_original_fact_expiries() {
        use super::*;
        let now = tokio::time::Instant::now();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let bitmap = DomainRouting { bitmap: [1; 8] };
        let expiry = Some(now + std::time::Duration::from_secs(30));
        let budget = MemoryBudget::new(4096);
        let scope = Scope {
            revision: 7,
            generation: 4,
            fingerprint: [3; 32],
            facts: vec![(
                super::super::maps::ip_addr_to_lpm_key(ip).data,
                bitmap,
                99,
                expiry,
            )],
            _memory: budget.reserve(512).unwrap(),
        };
        assert!(scope.matches(7, 4, [3; 32], now, [(ip, bitmap, expiry)].into_iter()));
        let extension = Some(now + std::time::Duration::from_secs(60));
        assert!(!scope.matches(7, 4, [3; 32], now, [(ip, bitmap, extension)].into_iter()));
        assert!(!scope.matches(
            7,
            4,
            [3; 32],
            now,
            [(ip, DomainRouting::default(), expiry)].into_iter()
        ));
        assert!(!scope.matches(7, 4, [3; 32], now, [].into_iter()));
        let expired_ip = "192.0.2.0".parse().unwrap();
        assert!(scope.matches(
            7,
            4,
            [3; 32],
            now,
            [(expired_ip, bitmap, Some(now)), (ip, bitmap, expiry)].into_iter()
        ));
    }

    #[test]
    #[ignore = "requires CAP_BPF"]
    fn native_emitted_rule_and_fallback_preserve_keep_set_zero_and_full_width() {
        use super::*;
        use aya_obj::generated::{bpf_attr, bpf_insn};
        use honk_ebpf_common::{
            KernelRouteOutput, ROUTING_MARK_KEEP, ROUTING_MARK_SET, RoutingDecision,
        };

        fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> bpf_insn {
            bpf_insn {
                code,
                _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
                off,
                imm,
            }
        }

        #[repr(C)]
        struct Run {
            program: u32,
            result: u32,
            input_bytes: u32,
            output_bytes: u32,
            input: u64,
            output: u64,
            repeat: u32,
            duration: u32,
        }

        let budget = MemoryBudget::new(512 << 20);
        let scratch = Map::new(&budget, 2, 4, size_of::<NativeScratch>(), 1, 0).unwrap();
        let domain = Map::new(&budget, 1, 16, size_of::<DomainRouting>(), 1, 0).unwrap();
        let ids = HashMap::from([("direct".to_owned(), 0), ("block".to_owned(), 1)]);
        for host in [false, true] {
            for mark in [None, Some(0), Some(0x8000_0000), Some(u32::MAX)] {
                for fallback in [false, true] {
                    let action = mark.map_or_else(
                        || "direct".to_owned(),
                        |mark| format!("direct(mark: {mark})"),
                    );
                    let source = if fallback {
                        format!("routing {{ default: {action} }}")
                    } else {
                        format!("routing {{\n dport(443) -> {action}\n default: block\n}}")
                    };
                    let config = honk_config::parser::parse_dae_config(&source).unwrap();
                    let router = crate::routing::Router::from_config(&config.routing).unwrap();
                    let plan =
                        RoutingPushPlan::compile(&router, &ids, honk_config::types::DialMode::Ip)
                            .unwrap();
                    let facts = Facts::new(&budget, &plan.facts).unwrap();
                    let emitted = if host {
                        crate::control::routing_matcher::codegen::emit_host_routing_program(
                            &plan,
                            facts.fds(domain.fd()),
                        )
                    } else {
                        emit_routing_program(&plan, facts.fds(domain.fd()))
                    }
                    .unwrap();
                    let mut program = vec![
                        insn(0x7a, 10, 0, if host { -512 } else { -8 }, 0),
                        insn(0x18, 1, 1, 0, scratch.fd()),
                        insn(0, 0, 0, 0, 0),
                        insn(0x62, 10, 0, -4, 0),
                        insn(0xbf, 2, 10, 0, 0),
                        insn(0x07, 2, 0, 0, -4),
                        insn(0x85, 0, 0, 0, 1),
                        insn(0x15, 0, 0, 6, 0),
                        insn(0xbf, 1, 0, 0, 0),
                        insn(0x07, 1, 0, 0, offset_of!(NativeScratch, input) as i32),
                        insn(0xbf, 2, 0, 0, 0),
                        insn(0x07, 2, 0, 0, offset_of!(NativeScratch, output) as i32),
                        insn(0x85, 0, 1, 0, 3),
                        insn(0x95, 0, 0, 0, 0),
                        insn(0xb7, 0, 0, 0, 1),
                        insn(0x95, 0, 0, 0, 0),
                    ];
                    program.extend_from_slice(&emitted.insns);
                    let mut log = vec![0u8; 1 << 20];
                    let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
                    attr.__bindgen_anon_3.prog_type = 1;
                    attr.__bindgen_anon_3.insn_cnt = program.len() as u32;
                    attr.__bindgen_anon_3.insns = program.as_ptr() as u64;
                    attr.__bindgen_anon_3.license = c"GPL".as_ptr() as u64;
                    attr.__bindgen_anon_3.log_level = 1;
                    attr.__bindgen_anon_3.log_size = log.len() as u32;
                    attr.__bindgen_anon_3.log_buf = log.as_mut_ptr() as u64;
                    let loaded = bpf(5, &mut attr);
                    assert!(
                        loaded.is_ok(),
                        "{loaded:?}: {}",
                        String::from_utf8_lossy(&log)
                    );
                    let program = unsafe { OwnedFd::from_raw_fd(loaded.unwrap()) };
                    let mut input = NativeScratch::default();
                    input.input.dst_port = 443;
                    input.input.ip_version = honk_ebpf_common::IpVersionType::V4 as u32;
                    input.input.l4proto = honk_ebpf_common::L4ProtoType::Tcp as u32;
                    input.output = KernelRouteOutput {
                        decision: RoutingDecision {
                            mark: 0xdead_beef,
                            ..Default::default()
                        },
                        mark_kind: 99,
                        generation: 123,
                        policy_id: 321,
                        fact_state: 456,
                        ..Default::default()
                    };
                    scratch.insert(&0u32, &input, 0).unwrap();
                    let packet = [0u8; 64];
                    let mut run = Run {
                        program: program.as_raw_fd() as u32,
                        result: u32::MAX,
                        input_bytes: packet.len() as u32,
                        output_bytes: 0,
                        input: packet.as_ptr() as u64,
                        output: 0,
                        repeat: 1,
                        duration: 0,
                    };
                    bpf(10, &mut run).unwrap();
                    assert_eq!(run.result, 0);
                    let output = scratch
                        .lookup::<_, NativeScratch>(&0u32)
                        .unwrap()
                        .unwrap()
                        .output;
                    assert_eq!(output.generation, 123);
                    assert_eq!(output.policy_id, 321);
                    assert_eq!(output.fact_state, 456);
                    let observed = output;
                    assert_eq!(observed.decision.outbound, 0);
                    assert_eq!(
                        observed.mark_kind,
                        if mark.is_some() {
                            ROUTING_MARK_SET
                        } else {
                            ROUTING_MARK_KEEP
                        },
                    );
                    assert_eq!(observed.decision.mark, mark.unwrap_or(0));
                    assert_eq!(
                        observed.decision.rule_id,
                        if fallback { u32::MAX } else { plan.rules[0].id },
                    );
                }
            }
        }
    }

    #[test]
    #[ignore = "requires CAP_BPF"]
    fn empty_native_fact_tries_are_created_despite_zero_memlock() {
        use super::*;
        // Cover all 4096 admitted possible CPUs; this test isolates memlock readback.
        let budget = MemoryBudget::new(512 << 20);
        Facts::new(&budget, &RoutingFactMaps::default()).unwrap();
    }

    #[test]
    fn full_native_trie_reserves_before_map_creation() {
        use super::*;
        let budget = MemoryBudget::new(192_512);
        let error = Map::new(
            &budget,
            LPM_TRIE,
            size_of::<LpmKey>(),
            size_of::<DomainRouting>(),
            1024,
            1,
        )
        .err()
        .expect("a full trie must exceed the old reservation");
        assert_eq!(error.to_string(), "native shared memory budget exhausted");
    }

    #[test]
    fn lpm_reservation_covers_replacement_nodes_and_per_cpu_caches() {
        use super::*;
        let one = lpm_trie_bytes(20, 32, 1).unwrap();
        let two = lpm_trie_bytes(20, 32, 2).unwrap();
        // A replacing update allocates before the old node is freed: two 96-byte slab objects per fill write.
        assert!(two - one >= 2 * 96);
        let cpus = aya::util::nr_cpus().unwrap().get() as usize;
        // The 7.2.5 per-CPU caches may hold high plus one refill batch of 96-byte units.
        assert!(one >= cpus * (96 + 48) * 96);
    }

    #[test]
    fn maintenance_preflight_requires_complete_stable_open_traversal() {
        use super::*;
        use std::cell::Cell;

        let keys = [
            NativeKey::default(),
            NativeKey {
                src_port: 1,
                ..Default::default()
            },
        ];
        let visited = Cell::new(0usize);
        assert!(
            !scan_claim_candidates(
                2,
                || 3,
                |previous| {
                    let index = visited.get();
                    assert_eq!(previous, index.checked_sub(1).map(|index| &keys[index]));
                    visited.set(index + 1);
                    Ok(keys.get(index).copied())
                },
                |_| Ok(Some(NativeClaim::default())),
                |_, _| false,
            )
            .unwrap()
        );
        assert_eq!(visited.get(), 3);

        for closed in [0, 2] {
            assert!(
                scan_claim_candidates(
                    1,
                    || closed,
                    |_| panic!("closed epochs cannot authorize an open scan"),
                    |_| panic!("closed epochs cannot authorize a claim lookup"),
                    |_, _| false,
                )
                .unwrap()
            );
        }
        for changed in [4, 5] {
            let epoch = Cell::new(3);
            assert!(
                scan_claim_candidates(
                    1,
                    || epoch.get(),
                    |previous| Ok(previous.is_none().then_some(keys[0])),
                    |_| Ok(Some(NativeClaim::default())),
                    |_, _| {
                        epoch.set(changed);
                        false
                    },
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn maintenance_preflight_preserves_candidates_missing_values_bounds_and_errors() {
        use super::*;

        let key = NativeKey::default();
        assert!(
            scan_claim_candidates(
                1,
                || 3,
                |_| Ok(Some(key)),
                |_| Ok(None),
                |_, _| panic!("a missing claim must remain uncertain"),
            )
            .unwrap()
        );

        for candidate in [false, true] {
            let mut steps = 0;
            assert!(
                scan_claim_candidates(
                    1,
                    || 3,
                    |_| {
                        steps += 1;
                        Ok(Some(key))
                    },
                    |_| Ok(Some(NativeClaim::default())),
                    |_, _| candidate,
                )
                .unwrap()
            );
            assert_eq!(steps, if candidate { 1 } else { 2 });
        }
        for lookup_error in [false, true] {
            let error = scan_claim_candidates(
                1,
                || 3,
                |_| {
                    if lookup_error {
                        Ok(Some(key))
                    } else {
                        Err(io::Error::from_raw_os_error(libc::EIO))
                    }
                },
                |_| Err(io::Error::from_raw_os_error(libc::EIO)),
                |_, _| false,
            )
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
        }
    }

    #[test]
    fn refused_or_changed_kernel_queries_retry_instead_of_retiring_a_bridge() {
        use super::{Ordering, checked_query};
        use std::sync::atomic::AtomicU64;
        let epoch = AtomicU64::new(4);
        let current = || epoch.load(Ordering::SeqCst);
        assert_eq!(
            checked_query(4, || Err(std::io::ErrorKind::WouldBlock.into()), current),
            None
        );
        assert_eq!(
            checked_query(
                4,
                || {
                    epoch.store(6, Ordering::SeqCst);
                    Ok(false)
                },
                current
            ),
            None
        );
        assert_eq!(checked_query(6, || Ok(false), current), Some(false));
        assert_eq!(checked_query(6, || Ok(true), current), Some(true));
    }
    #[test]
    fn overlapping_writers_and_failed_siblings_cannot_reopen() {
        assert_eq!(next_closed(0), Some(2));
        assert_eq!(next_closed(2), Some(4));
        assert_eq!(next_closed(5), Some(6));
        assert_eq!(next_closed(u64::MAX - 1), None);
        assert_eq!(next_closed(u64::MAX), None);
        let mut writers = Writers::default();
        writers.begin().unwrap();
        writers.begin().unwrap();
        assert!(!writers.finish(true));
        assert!(writers.finish(true));
        writers.begin().unwrap();
        writers.begin().unwrap();
        assert!(!writers.finish(false));
        assert!(!writers.finish(true));
        assert!(writers.begin().is_err());
        let mut terminal = Writers::default();
        terminal.begin().unwrap();
        terminal.terminal = true;
        assert!(!terminal.finish(true));
        assert!(terminal.begin().is_err());
    }

    #[test]
    fn physical_publication_refuses_every_explicit_set_effect() {
        use super::admit_physical_effects;
        use crate::control::routing_matcher::KernelRule;

        let (publication, _) = publication_basis_fixture();
        let mut plan = publication.state.lock().plan.clone().unwrap();
        admit_physical_effects(&plan).unwrap();
        for mark in [0, 9, 0x8000_0000, u32::MAX] {
            plan.fallback.mark = Some(mark);
            assert!(
                admit_physical_effects(&plan).is_err(),
                "fallback Set({mark})"
            );
            plan.fallback.mark = None;
            plan.rules.push(KernelRule {
                id: 7,
                source: String::new(),
                action: crate::control::routing_matcher::KernelAction {
                    mark: Some(mark),
                    ..plan.fallback
                },
                conditions: Vec::new(),
            });
            assert!(admit_physical_effects(&plan).is_err(), "rule Set({mark})");
            plan.rules[0].action.mark = None;
            admit_physical_effects(&plan).unwrap();
            plan.rules.clear();
        }
    }

    #[test]
    fn reply_blocks_require_a_tuple_known_prefix_and_matching_rule() {
        use super::{KernelPredicate as Predicate, RoutingPushPlan, reply_block_rules};
        use crate::control::routing_matcher::{KernelAction, KernelCondition, KernelRule};
        use crate::routing::PortRange;
        use honk_ebpf_common::OutboundIndex::{Block, Direct};

        fn action(outbound: honk_ebpf_common::OutboundIndex) -> KernelAction {
            KernelAction {
                outbound: outbound as u8,
                must: false,
                mark: None,
                direct_mark_index: None,
            }
        }
        fn rule(
            id: u32,
            outbound: honk_ebpf_common::OutboundIndex,
            predicates: Vec<Predicate>,
        ) -> KernelRule {
            KernelRule {
                id,
                source: String::new(),
                action: action(outbound),
                conditions: predicates
                    .into_iter()
                    .map(|predicate| KernelCondition {
                        not: false,
                        predicate,
                    })
                    .collect(),
            }
        }
        fn plan(rules: Vec<KernelRule>, block_fallback: bool) -> RoutingPushPlan {
            let has_domain_rules = rules.iter().any(|rule| {
                rule.conditions
                    .iter()
                    .any(|condition| matches!(condition.predicate, Predicate::Domain(_)))
            });
            RoutingPushPlan {
                rules,
                facts: Default::default(),
                fallback: action(if block_fallback { Block } else { Direct }),
                features: if has_domain_rules {
                    honk_ebpf_common::ROUTING_FEATURE_DOMAIN
                } else {
                    0
                },
                fingerprint: [0; 32],
                policy_fingerprint: [0; 32],
                has_domain_rules,
                domain_predicate_count: usize::from(has_domain_rules),
                trace_enabled: false,
            }
        }

        let block = rule(
            17,
            Block,
            vec![
                Predicate::DestinationIp(0),
                Predicate::SourceIp(1),
                Predicate::DestinationPort(vec![PortRange {
                    start: 443,
                    end: 443,
                }]),
                Predicate::SourcePort(vec![PortRange {
                    start: 1234,
                    end: 1234,
                }]),
                Predicate::Protocol(1),
                Predicate::IpVersion(1),
            ],
        );
        let known_prefix = rule(7, Direct, vec![Predicate::Protocol(2)]);
        assert_eq!(
            reply_block_rules(&plan(vec![known_prefix, block.clone()], true)),
            [17, u32::MAX]
        );
        assert_eq!(reply_block_rules(&plan(vec![block.clone()], false)), [17]);
        assert_eq!(reply_block_rules(&plan(Vec::new(), true)), [u32::MAX]);
        assert!(reply_block_rules(&plan(Vec::new(), false)).is_empty());

        for unknown in [
            Predicate::Domain(0),
            Predicate::Dscp(vec![8]),
            Predicate::Mac(0),
            Predicate::ProcessName(vec![b"curl".to_vec()]),
        ] {
            for not in [false, true] {
                let mut prefix = rule(7, Direct, vec![unknown.clone()]);
                prefix.conditions[0].not = not;
                assert!(
                    reply_block_rules(&plan(vec![prefix.clone(), block.clone()], true)).is_empty()
                );
                assert_eq!(
                    reply_block_rules(&plan(vec![block.clone(), prefix], true)),
                    [17]
                );
                let mut matching = rule(17, Block, vec![Predicate::Protocol(1), unknown.clone()]);
                matching.conditions[1].not = not;
                assert!(reply_block_rules(&plan(vec![matching], true)).is_empty());
            }
        }

        // An impossible earlier domain rule is omitted by the canonical emitter.
        let impossible = rule(
            7,
            Direct,
            vec![Predicate::Domain(0), Predicate::Protocol(0)],
        );
        assert_eq!(
            reply_block_rules(&plan(vec![impossible, block], true)),
            [17, u32::MAX]
        );
        // Negated empty predicates are folded true; they need no reply facts.
        let mut folded = rule(
            17,
            Block,
            vec![Predicate::Dscp(Vec::new()), Predicate::Protocol(1)],
        );
        folded.conditions[0].not = true;
        assert_eq!(
            reply_block_rules(&plan(vec![folded.clone()], true)),
            [17, u32::MAX]
        );
        folded.conditions.pop();
        // This rule is now unconditional, so the fallback is unreachable.
        assert_eq!(reply_block_rules(&plan(vec![folded], true)), [17]);
    }
}
