//! Bounded publication evidence and descriptor-relative, durability-classified export.
//! Live writer authority and the last actual stored epoch survive journal eviction;
//! completeness replays only retained evidence and never grants runtime authority.

use super::{clock_ns, reserve};
use anyhow::{Context as _, ensure};
use honk_ebpf_common::xdp::*;
use honk_netstack::{MemoryBudget, MemoryReservation};
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat, renameat};
use nix::sys::stat::{Mode, fstatat, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde::ser::{Serialize, SerializeSeq, SerializeStruct, Serializer};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{self, Read as _, Write};
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

type Event = NativePublicationEventV1;
const CAPACITY: usize = 4096;
const CAPTURED_CAPACITY: usize = 256;
const CAPTURED_REALM_CAPACITY: usize = 128;
const CAPTURED_PIN_PATH_BYTES: usize = 4096;
const OWNER_BYTES: usize = 8192;
const BUFFER_BYTES: usize = 65536;
const MAX_HOOKS: usize = 32;
const SCHEMA: &str = "native-publication/v1";
const KNOWN_EVENT_FLAGS: u32 = 511;
static SERIAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeExportPublicationResult {
    NotPublished,
    PublishedDurabilityUnknown,
    PublishedDurable,
}
impl NativeExportPublicationResult {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotPublished => "NOT_PUBLISHED",
            Self::PublishedDurabilityUnknown => "PUBLISHED_DURABILITY_UNKNOWN",
            Self::PublishedDurable => "PUBLISHED_DURABLE",
        }
    }
}

#[derive(Debug)]
pub(crate) struct NativeExportResult {
    pub(crate) status: NativeExportPublicationResult,
    pub(crate) error: Option<anyhow::Error>,
    pub(crate) path: Option<PathBuf>,
    pub(crate) sha256: Option<String>,
    pub(crate) bytes: u64,
    pub(crate) boot_id: [u8; 36],
    pub(crate) pid: u32,
    pub(crate) starttime_ticks: u64,
    pub(crate) publication_serial: u64,
    pub(crate) root_map_id: u32,
    pub(crate) final_export: bool,
    pub(crate) complete: bool,
    pub(crate) last_seq: u64,
}
impl NativeExportResult {
    pub(crate) fn record(&self) {
        tracing::info!(
            export_publication_result = self.status.as_str(),
            path = ?self.path, sha256 = ?self.sha256, bytes = self.bytes,
            boot_id = %String::from_utf8_lossy(&self.boot_id), pid = self.pid,
            starttime_ticks = self.starttime_ticks, publication_serial = self.publication_serial,
            root_map_id = self.root_map_id, final_export = self.final_export,
            complete = self.complete, last_seq = self.last_seq,
            export_error = ?self.error, "Native publication artifact result"
        );
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Snapshot {
    pub(super) epoch: u64,
    pub(super) flags: u32,
    pub(super) ready: bool,
    pub(super) capture_ready: bool,
    pub(super) failed: bool,
    pub(super) terminal: bool,
    pub(super) hooks_joined: bool,
    pub(super) all_counters_sealed: bool,
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct HookIdentity {
    pub(super) hook_id: u64,
    pub(super) target_serial: u64,
    pub(super) kind: u32,
    pub(super) scope: u64,
    pub(super) namespace_cookie: u64,
    pub(super) ifindex: u32,
    pub(super) attachment_generation: u64,
    pub(super) counter_map_id: u32,
    pub(super) program_id: u32,
}
#[derive(Clone, Copy, Default)]
struct Hook {
    identity: HookIdentity,
    registered_seq: u64,
    current_program: u32,
    current_generation: u64,
    pending_old: u32,
    pending_new: u32,
    pending_operation: u64,
    pending_writer: u64,
    pending_reason: u32,
}
struct Destination {
    directory: File,
    path: PathBuf,
    name: String,
    installed: Option<File>,
}

#[derive(Clone, Copy)]
struct LiveOperation {
    writer_id: u64,
    root_operation_id: u64,
    operation_id: u64,
    reason: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct CapturedReceipt {
    pub(super) seq: u64,
    pub(super) kind: &'static str,
    pub(super) key: Option<NativeKey>,
    pub(super) claim_epoch: Option<u64>,
    pub(super) claim_incarnation: Option<u64>,
    pub(super) claim_scope: Option<u64>,
    pub(super) producer_epoch: Option<u64>,
    pub(super) producer_incarnation: Option<u64>,
    pub(super) producer_expires_boottime_ns: Option<u64>,
    pub(super) producer_flags: Option<u32>,
    pub(super) basis_epoch: Option<u64>,
    pub(super) routing_generation: Option<u64>,
    pub(super) routing_fingerprint: Option<[u8; 32]>,
    pub(super) mode_revision: Option<u64>,
    pub(super) basis_flags: Option<u32>,
    pub(super) fact_scope: Option<u64>,
    pub(super) fact_revision: Option<u64>,
    pub(super) fact_horizon: Option<u64>,
    pub(super) return_attachment: Option<u64>,
    pub(super) slot: Option<u64>,
    pub(super) op_incarnation: Option<u64>,
    pub(super) completion_handle: Option<[u64; 4]>,
    pub(super) outcome: Option<&'static str>,
    pub(super) entry_seq: Option<u64>,
    pub(super) fresh_grace: Option<bool>,
    pub(super) boottime_ns: Option<u64>,
    pub(super) related_seq: Option<u64>,
    pub(super) inventory_held: Option<u64>,
    pub(super) inventory_pending: Option<u64>,
    pub(super) inventory_flight: Option<u64>,
    pub(super) count_before: Option<u64>,
    pub(super) count_after: Option<u64>,
    pub(super) phase_after: Option<u32>,
    pub(super) terminal: Option<bool>,
    pub(super) joined_receipt_file: Option<CapturedJoinedReceiptFile>,
    pub(super) terminal_inventory_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct CapturedJoinedReceiptFile {
    bytes: [u8; 255],
    len: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub(super) enum CapturedRealmState {
    Installed,
    #[serde(rename = "retired-pending")]
    RetiredPending,
}

#[derive(Clone, Copy)]
pub(super) struct CapturedRealmCandidate<'a> {
    pub(super) pin_path: &'a Path,
    pub(super) program_id: u32,
    pub(super) realm_index: u32,
    pub(super) closed_epoch: u64,
    pub(super) state: CapturedRealmState,
}

#[derive(Clone)]
struct CapturedRealm {
    pin_path: [u8; CAPTURED_PIN_PATH_BYTES],
    closed_epoch: u64,
    program_id: u32,
    realm_index: u32,
    pin_path_len: u16,
    state: CapturedRealmState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub(super) enum CapturedInventoryStatus {
    Committed,
    Failed,
    Partial,
}

#[derive(Clone, Copy)]
struct CapturedInventory {
    return_attachment: u64,
    inventory_seq: u64,
    boottime_ns: u64,
    status: CapturedInventoryStatus,
    len: usize,
}

pub(super) struct Recording {
    ring: Vec<Event>,
    head: usize,
    len: usize,
    captured_ring: Vec<CapturedReceipt>,
    captured_head: usize,
    captured_len: usize,
    captured_last_seq: u64,
    captured_receipts_evicted: u64,
    captured_realms: Vec<CapturedRealm>,
    captured_inventory: Option<CapturedInventory>,
    last_seq: u64,
    total_appended: u64,
    overwritten_events: u64,
    last_operation: u64,
    last_writer: u64,
    last_started_writer: u64,
    last_started_operation: u64,
    actual_epoch: u64,
    live_operations: Vec<LiveOperation>,
    budget: Arc<MemoryBudget>,
    live_memory: [Option<MemoryReservation>; usize::BITS as usize],
    serial: u64,
    root_map_id: u32,
    boot_id: [u8; 36],
    pid: u32,
    starttime_ticks: u64,
    collection_start: Option<u64>,
    hooks: [Hook; MAX_HOOKS],
    hook_count: usize,
    buffer: Option<Vec<u8>>,
    destination: Option<Destination>,
    initial_manifest: Option<([u8; 32], u64)>,
    export_error: bool,
    pub(super) recording_error: bool,
    pub(super) clock_error: bool,
    pub(super) accounting_error: bool,
    pub(super) counter_overflow: bool,
    pub(super) completed: bool,
    pub(super) hooks_joined: bool,
    _memory: MemoryReservation,
    _top_up: Option<MemoryReservation>,
    #[cfg(test)]
    fault: Option<ExportFault>,
    #[cfg(test)]
    fail_clock: bool,
}
const _: () = assert!(size_of::<Recording>() <= OWNER_BYTES);
impl Recording {
    pub(super) fn new(budget: &Arc<MemoryBudget>, root_map_id: u32) -> anyhow::Result<Self> {
        Self::allocate(budget, root_map_id, CAPACITY, BUFFER_BYTES, false)
    }
    #[cfg(test)]
    pub(super) fn test_new(budget: &Arc<MemoryBudget>) -> anyhow::Result<Self> {
        Self::allocate(budget, 1, 32, 4096, true)
    }
    fn reservation_bytes(capacity: usize, buffer_bytes: usize) -> anyhow::Result<usize> {
        capacity
            .checked_mul(size_of::<Event>())
            .and_then(|n| n.checked_add(CAPTURED_CAPACITY * size_of::<CapturedReceipt>()))
            .and_then(|n| n.checked_add(CAPTURED_REALM_CAPACITY * size_of::<CapturedRealm>()))
            .and_then(|n| n.checked_add(OWNER_BYTES.max(size_of::<Self>())))
            .and_then(|n| n.checked_add(buffer_bytes))
            .context("Native journal reservation overflow")
    }

    #[cfg(test)]
    pub(super) fn test_replacement_peak_bytes() -> anyhow::Result<usize> {
        Self::reservation_bytes(32, 4096)?
            .checked_add(Self::reservation_bytes(CAPACITY, BUFFER_BYTES)?)
            .context("Native journal replacement reservation overflow")
    }

    fn allocate(
        budget: &Arc<MemoryBudget>,
        root_map_id: u32,
        capacity: usize,
        buffer_bytes: usize,
        dummy: bool,
    ) -> anyhow::Result<Self> {
        ensure!(
            capacity != 0 && capacity <= CAPACITY,
            "invalid Native journal capacity"
        );
        let bytes = Self::reservation_bytes(capacity, buffer_bytes)?;
        let memory = reserve(budget, bytes)?;
        let mut ring = Vec::new();
        ring.try_reserve_exact(capacity)?;
        ring.resize(capacity, Event::default());
        let mut captured_ring = Vec::new();
        captured_ring.try_reserve_exact(CAPTURED_CAPACITY)?;
        captured_ring.resize(CAPTURED_CAPACITY, CapturedReceipt::default());
        let mut captured_realms = Vec::new();
        captured_realms.try_reserve_exact(CAPTURED_REALM_CAPACITY)?;
        captured_realms.resize(
            CAPTURED_REALM_CAPACITY,
            CapturedRealm {
                pin_path: [0; CAPTURED_PIN_PATH_BYTES],
                closed_epoch: 0,
                program_id: 0,
                realm_index: 0,
                pin_path_len: 0,
                state: CapturedRealmState::Installed,
            },
        );
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(buffer_bytes)?;
        buffer.resize(buffer_bytes, 0);
        let actual = ring
            .capacity()
            .checked_mul(size_of::<Event>())
            .and_then(|n| {
                captured_ring
                    .capacity()
                    .checked_mul(size_of::<CapturedReceipt>())
                    .and_then(|captured| n.checked_add(captured))
            })
            .and_then(|n| {
                captured_realms
                    .capacity()
                    .checked_mul(size_of::<CapturedRealm>())
                    .and_then(|inventory| n.checked_add(inventory))
            })
            .and_then(|n| n.checked_add(buffer.capacity()))
            .and_then(|n| n.checked_add(OWNER_BYTES.max(size_of::<Self>())))
            .context("Native journal allocation overflow")?;
        let top_up = if actual > bytes {
            Some(reserve(budget, actual - bytes)?)
        } else {
            None
        };
        let serial = SERIAL
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| anyhow::anyhow!("Native publication serial exhausted"))?
            + 1;
        let (boot_id, pid, starttime_ticks) = if dummy {
            (*b"00000000-0000-0000-0000-000000000000", 1, 1)
        } else {
            process_identity()?
        };
        let mut recording = Self {
            ring,
            head: 0,
            len: 0,
            captured_ring,
            captured_head: 0,
            captured_len: 0,
            captured_last_seq: 0,
            captured_receipts_evicted: 0,
            captured_realms,
            captured_inventory: None,
            last_seq: 0,
            total_appended: 0,
            overwritten_events: 0,
            last_operation: 0,
            last_writer: 0,
            serial,
            root_map_id,
            boot_id,
            pid,
            starttime_ticks,
            last_started_writer: 0,
            last_started_operation: 0,
            actual_epoch: 0,
            live_operations: Vec::new(),
            budget: Arc::clone(budget),
            live_memory: std::array::from_fn(|_| None),
            collection_start: None,
            hooks: [Hook::default(); MAX_HOOKS],
            hook_count: 0,
            buffer: Some(buffer),
            destination: None,
            initial_manifest: None,
            export_error: false,
            recording_error: false,
            clock_error: false,
            accounting_error: false,
            counter_overflow: false,
            completed: false,
            hooks_joined: false,
            _memory: memory,
            _top_up: top_up,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            fail_clock: false,
        };
        let timestamp = recording.time();
        recording.collection_start = timestamp;
        recording.append(Event {
            kind: NATIVE_EVENT_INITIAL_STATE,
            reason: NativeReason::Startup as u32,
            boottime_before_ns: timestamp.unwrap_or(0),
            boottime_after_ns: timestamp.unwrap_or(0),
            flags: if timestamp.is_some() {
                NATIVE_EVENT_FLAG_TIMESTAMP_VALID
            } else {
                0
            },
            ..Event::default()
        });
        ensure!(
            !recording.clock_error,
            "Native initial BOOTTIME unavailable"
        );
        Ok(recording)
    }
    pub(super) fn captured(&mut self, mut receipt: CapturedReceipt) -> u64 {
        let Some(seq) = self.captured_last_seq.checked_add(1) else {
            self.recording_error = true;
            return 0;
        };
        let evicted = if self.captured_len == CAPTURED_CAPACITY {
            let Some(evicted) = self.captured_receipts_evicted.checked_add(1) else {
                self.recording_error = true;
                return 0;
            };
            evicted
        } else {
            self.captured_receipts_evicted
        };
        receipt.seq = seq;
        self.captured_ring[(self.captured_head + self.captured_len) % CAPTURED_CAPACITY] = receipt;
        if self.captured_len == CAPTURED_CAPACITY {
            self.captured_head = (self.captured_head + 1) % CAPTURED_CAPACITY;
        } else {
            self.captured_len += 1;
        }
        self.captured_last_seq = seq;
        self.captured_receipts_evicted = evicted;
        seq
    }
    pub(super) fn captured_joined_ack(
        &mut self,
        return_attachment: u64,
        filename: &str,
        terminal_inventory_sha256: [u8; 32],
    ) -> anyhow::Result<u64> {
        let result = (|| {
            ensure!(
                !filename.is_empty()
                    && filename.len() <= 255
                    && filename != "."
                    && filename != ".."
                    && !filename.bytes().any(|b| b == b'/' || b == 0),
                "Native captured joined receipt filename invalid"
            );
            let mut file = CapturedJoinedReceiptFile {
                bytes: [0; 255],
                len: filename.len() as u8,
            };
            file.bytes[..filename.len()].copy_from_slice(filename.as_bytes());
            let seq = self.captured(CapturedReceipt {
                kind: "CAPTURED_JOINED_ACK",
                return_attachment: Some(return_attachment),
                joined_receipt_file: Some(file),
                terminal_inventory_sha256: Some(terminal_inventory_sha256),
                ..CapturedReceipt::default()
            });
            ensure!(
                seq != 0,
                "Native captured joined receipt acknowledgement unavailable"
            );
            Ok(seq)
        })();
        if result.is_err() {
            self.accounting_error = true;
            self.recording_error = true;
        }
        result
    }
    /// Replace the current inventory from retained objects after a writer attempt finishes.
    pub(super) fn captured_inventory<'a>(
        &mut self,
        return_attachment: u64,
        status: CapturedInventoryStatus,
        entries: impl Iterator<Item = CapturedRealmCandidate<'a>>,
    ) -> anyhow::Result<()> {
        let result = (|| {
            let mut candidates = [None; CAPTURED_REALM_CAPACITY];
            let mut len = 0;
            for entry in entries {
                ensure!(
                    len < CAPTURED_REALM_CAPACITY,
                    "Native captured realm inventory capacity exceeded"
                );
                let path = entry.pin_path.as_os_str().as_bytes();
                ensure!(
                    !path.is_empty() && path.len() <= CAPTURED_PIN_PATH_BYTES && !path.contains(&0),
                    "Native captured realm pin path length or bytes invalid"
                );
                ensure!(
                    entry.pin_path.to_str().is_some(),
                    "Native captured realm pin path is not UTF-8"
                );
                candidates[len] = Some(entry);
                len += 1;
            }
            let inventory_seq = self
                .captured_inventory
                .map_or(0, |i| i.inventory_seq)
                .checked_add(1)
                .context("Native captured realm inventory sequence exhausted")?;
            let boottime_ns = self
                .time()
                .context("Native captured realm inventory BOOTTIME unavailable")?;
            for (slot, entry) in self
                .captured_realms
                .iter_mut()
                .zip(candidates[..len].iter().flatten())
            {
                let path = entry.pin_path.as_os_str().as_bytes();
                slot.pin_path[..path.len()].copy_from_slice(path);
                slot.pin_path_len = path.len() as u16;
                slot.program_id = entry.program_id;
                slot.realm_index = entry.realm_index;
                slot.closed_epoch = entry.closed_epoch;
                slot.state = entry.state;
            }
            self.captured_inventory = Some(CapturedInventory {
                return_attachment,
                inventory_seq,
                boottime_ns,
                status,
                len,
            });
            Ok(())
        })();
        if result.is_err() {
            self.accounting_error = true;
            self.recording_error = true;
        }
        result
    }
    pub(super) fn set_root_map_id(&mut self, id: u32) -> anyhow::Result<()> {
        ensure!(
            id != 0 && self.root_map_id == 0 && self.initial_manifest.is_none(),
            "Native root map identity already bound or invalid"
        );
        self.root_map_id = id;
        Ok(())
    }
    pub(super) fn identity(&self) -> u64 {
        self.serial
    }
    pub(super) fn operation(&mut self) -> u64 {
        match self.last_operation.checked_add(1) {
            Some(id) => {
                self.last_operation = id;
                id
            }
            None => {
                self.recording_error = true;
                0
            }
        }
    }
    pub(super) fn writer(&mut self) -> u64 {
        match self.last_writer.checked_add(1) {
            Some(id) => {
                self.last_writer = id;
                id
            }
            None => {
                self.recording_error = true;
                0
            }
        }
    }
    #[cfg(test)]
    pub(super) fn fail_clock_for_test(&mut self, fail: bool) {
        self.fail_clock = fail;
    }
    pub(super) fn time(&mut self) -> Option<u64> {
        #[cfg(test)]
        if self.fail_clock {
            self.clock_error = true;
            return None;
        }
        match clock_ns(libc::CLOCK_BOOTTIME) {
            Ok(value) => Some(value),
            Err(_) => {
                self.clock_error = true;
                None
            }
        }
    }
    pub(super) fn append(&mut self, mut event: Event) -> u64 {
        if validate_event(&event).is_err()
            || event.operation_id > self.last_operation
            || event.writer_id > self.last_writer
            || (event.writer_id != 0 && event.operation_id == 0)
            || !self.live_event_valid(&event)
            || (event.hook_id != 0
                && !self.hooks[..self.hook_count]
                    .iter()
                    .any(|h| h.identity.hook_id == event.hook_id))
        {
            self.recording_error = true;
            return 0;
        }
        self.counter_overflow |= event.flags & NATIVE_EVENT_FLAG_COUNTER_OVERFLOW != 0;
        let Some(seq) = self.last_seq.checked_add(1) else {
            self.recording_error = true;
            return 0;
        };
        let Some(total) = self.total_appended.checked_add(1) else {
            self.recording_error = true;
            return 0;
        };
        if event.kind == NATIVE_EVENT_WRITER_BEGIN && self.reserve_live_operation().is_err() {
            self.recording_error = true;
            return 0;
        }
        event.seq = seq;
        let index = if self.len < self.ring.len() {
            let index = (self.head + self.len) % self.ring.len();
            self.len += 1;
            index
        } else {
            let Some(loss) = self.overwritten_events.checked_add(1) else {
                self.recording_error = true;
                return 0;
            };
            self.overwritten_events = loss;
            let index = self.head;
            self.head = (self.head + 1) % self.ring.len();
            index
        };
        self.ring[index] = event;
        self.last_seq = seq;
        self.total_appended = total;
        match event.kind {
            NATIVE_EVENT_WRITER_BEGIN => {
                let root_operation_id = self
                    .live_operations
                    .iter()
                    .find(|op| op.writer_id == event.writer_id)
                    .map_or(event.operation_id, |op| op.root_operation_id);
                self.live_operations.push(LiveOperation {
                    writer_id: event.writer_id,
                    root_operation_id,
                    operation_id: event.operation_id,
                    reason: event.reason,
                });
                self.last_started_writer = self.last_started_writer.max(event.writer_id);
                self.last_started_operation = event.operation_id;
            }
            NATIVE_EVENT_WRITER_OUTCOME => {
                self.live_operations.retain(|op| {
                    op.operation_id != event.operation_id
                        && op.root_operation_id != event.operation_id
                });
            }
            NATIVE_EVENT_INITIAL_STATE | NATIVE_EVENT_CLOSE_STORED | NATIVE_EVENT_REOPEN_STORED => {
                self.actual_epoch = event.epoch_after;
            }
            _ => {}
        }
        seq
    }
    pub(super) fn events(&self) -> impl DoubleEndedIterator<Item = &Event> + ExactSizeIterator {
        (0..self.len).map(move |index| &self.ring[(self.head + index) % self.ring.len()])
    }
    pub(super) fn is_live_writer(&self, writer_id: u64, root_operation_id: u64) -> bool {
        self.live_operations.iter().any(|op| {
            op.writer_id == writer_id
                && op.operation_id == root_operation_id
                && op.root_operation_id == root_operation_id
        })
    }
    fn live_event_valid(&self, event: &Event) -> bool {
        if event.kind == NATIVE_EVENT_WRITER_BEGIN {
            return event.operation_id > self.last_started_operation
                && (self.live_operations.iter().any(|op| {
                    op.writer_id == event.writer_id && op.operation_id == op.root_operation_id
                }) || event.writer_id > self.last_started_writer);
        }
        if matches!(
            event.kind,
            NATIVE_EVENT_WRITER_OUTCOME | NATIVE_EVENT_PROGRAM_REPLACED
        ) {
            return self.live_operations.iter().any(|op| {
                op.writer_id == event.writer_id
                    && op.operation_id == event.operation_id
                    && op.reason == event.reason
                    && self.is_live_writer(op.writer_id, op.root_operation_id)
            });
        }
        true
    }
    fn reserve_live_operation(&mut self) -> anyhow::Result<()> {
        if self.live_operations.len() < self.live_operations.capacity() {
            return Ok(());
        }
        let capacity = self
            .live_operations
            .capacity()
            .max(4)
            .checked_mul(2)
            .context("Native live operation capacity exhausted")?;
        let slot = self
            .live_memory
            .iter()
            .position(Option::is_none)
            .context("Native live operation reservation capacity exhausted")?;
        let previous = self
            .live_operations
            .capacity()
            .checked_mul(size_of::<LiveOperation>())
            .context("Native live operation allocation overflow")?;
        let bytes = capacity
            .checked_sub(self.live_operations.capacity())
            .and_then(|n| n.checked_mul(size_of::<LiveOperation>()))
            .and_then(|n| n.checked_add(super::PAGE_BYTES))
            .context("Native live operation charge overflow")?;
        // Capacity charges outlive settled operations; growth also reserves the overlapping backing.
        let mut memory = reserve(&self.budget, bytes)?;
        let _growth = reserve(&self.budget, previous)?;
        let mut operations = Vec::new();
        operations.try_reserve_exact(capacity)?;
        let actual = operations
            .capacity()
            .checked_mul(size_of::<LiveOperation>())
            .context("Native live operation allocation overflow")?;
        if actual.saturating_sub(previous) > bytes {
            memory = reserve(&self.budget, actual - previous)?;
        }
        operations.extend_from_slice(&self.live_operations);
        self.live_operations = operations;
        self.live_memory[slot] = Some(memory);
        Ok(())
    }
    fn writer_event_valid(&self, event: &Event, before: usize) -> bool {
        if !matches!(
            event.kind,
            NATIVE_EVENT_WRITER_BEGIN | NATIVE_EVENT_WRITER_OUTCOME | NATIVE_EVENT_PROGRAM_REPLACED
        ) {
            return true;
        }
        let prior = || self.events().take(before);
        let root =
            prior().find(|e| e.kind == NATIVE_EVENT_WRITER_BEGIN && e.writer_id == event.writer_id);
        if root.is_some_and(|root| {
            prior().any(|e| {
                e.kind == NATIVE_EVENT_WRITER_OUTCOME
                    && e.writer_id == root.writer_id
                    && e.operation_id == root.operation_id
            })
        }) {
            return false;
        }
        let begin = prior()
            .find(|e| e.kind == NATIVE_EVENT_WRITER_BEGIN && e.operation_id == event.operation_id);
        if event.kind == NATIVE_EVENT_WRITER_BEGIN {
            return begin.is_none()
                && prior()
                    .filter(|e| e.kind == NATIVE_EVENT_WRITER_BEGIN)
                    .all(|e| {
                        e.operation_id < event.operation_id
                            && (root.is_some() || e.writer_id < event.writer_id)
                    });
        }
        root.is_some()
            && begin.is_some_and(|begin| {
                begin.writer_id == event.writer_id && begin.reason == event.reason
            })
            && !prior().any(|e| {
                e.kind == NATIVE_EVENT_WRITER_OUTCOME && e.operation_id == event.operation_id
            })
    }
    pub(super) fn register_hook(&mut self, identity: HookIdentity) -> anyhow::Result<()> {
        let closed = self.actual_epoch & 1 == 0;
        let valid = closed
            && (self.initial_manifest.is_some()
                || (cfg!(test) && self.destination.is_none() && !self.export_error))
            && self.hook_count < MAX_HOOKS
            && identity.hook_id != 0
            && identity.target_serial != 0
            && (identity.kind == 0 || identity.kind == 1)
            && identity.namespace_cookie != 0
            && identity.ifindex != 0
            && identity.attachment_generation != 0
            && identity.counter_map_id != 0
            && !self.hooks[..self.hook_count].iter().any(|h| {
                h.identity.hook_id == identity.hook_id
                    || (h.identity.target_serial == identity.target_serial
                        && (h.identity.kind == identity.kind
                            || h.identity.scope != identity.scope
                            || h.identity.namespace_cookie != identity.namespace_cookie
                            || h.identity.ifindex != identity.ifindex
                            || h.identity.counter_map_id != identity.counter_map_id))
                    || (h.identity.target_serial != identity.target_serial
                        && h.identity.counter_map_id == identity.counter_map_id)
            });
        if !valid {
            self.recording_error = true;
            anyhow::bail!("Native hook identity invalid, duplicate or table full");
        }
        self.hooks[self.hook_count] = Hook {
            identity,
            current_program: identity.program_id,
            current_generation: identity.attachment_generation,
            ..Hook::default()
        };
        self.hook_count += 1;
        let seq = self.append(Event {
            kind: NATIVE_EVENT_HOOK_REGISTERED,
            hook_id: identity.hook_id,
            reason: NativeReason::Startup as u32,
            counter_epoch: u64::from(identity.program_id),
            ..Event::default()
        });
        self.hooks[self.hook_count - 1].registered_seq = seq;
        ensure!(seq != 0, "Native hook registration was not recorded");
        Ok(())
    }
    #[allow(clippy::too_many_arguments)] // eight parameters; splitting into a struct adds churn across all callers
    pub(super) fn program_replacement(
        &mut self,
        hook_id: u64,
        old: u32,
        new: u32,
        outcome: u32,
        reason: NativeReason,
        operation_id: u64,
        writer_id: u64,
    ) -> anyhow::Result<()> {
        let Some(index) = self.hooks[..self.hook_count]
            .iter()
            .position(|h| h.identity.hook_id == hook_id)
        else {
            self.recording_error = true;
            anyhow::bail!("unknown Native replacement hook");
        };
        let hook = self.hooks[index];
        let epoch = self.actual_epoch;
        let valid = epoch & 1 == 0
            && operation_id != 0
            && writer_id != 0
            && new != 0
            && new != old
            && hook.current_program == old
            && match outcome {
                NATIVE_OUTCOME_PENDING => hook.pending_new == 0,
                NATIVE_OUTCOME_COMMITTED | NATIVE_OUTCOME_FAILED => {
                    hook.pending_old == old
                        && hook.pending_new == new
                        && hook.pending_operation == operation_id
                        && hook.pending_writer == writer_id
                        && hook.pending_reason == reason as u32
                }
                _ => false,
            };
        if !valid {
            self.recording_error = true;
            anyhow::bail!("Native replacement identity or outcome differs");
        }
        let seq = self.append(Event {
            kind: NATIVE_EVENT_PROGRAM_REPLACED,
            hook_id,
            counter_value: u64::from(old),
            counter_epoch: u64::from(new),
            outcome,
            reason: reason as u32,
            operation_id,
            writer_id,
            ..Event::default()
        });
        ensure!(seq != 0, "Native program replacement was not recorded");
        let hook = &mut self.hooks[index];
        if outcome == NATIVE_OUTCOME_PENDING {
            hook.pending_old = old;
            hook.pending_new = new;
            hook.pending_operation = operation_id;
            hook.pending_writer = writer_id;
            hook.pending_reason = reason as u32;
        } else {
            hook.pending_old = 0;
            hook.pending_new = 0;
            if outcome == NATIVE_OUTCOME_COMMITTED {
                let Some(generation) = hook.current_generation.checked_add(1) else {
                    self.recording_error = true;
                    anyhow::bail!("Native attachment generation exhausted");
                };
                hook.current_program = new;
                hook.current_generation = generation;
            } else {
                self.recording_error = true;
            }
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn initial_checkpoint(&self) -> Option<(PathBuf, [u8; 32], u64)> {
        let (hash, bytes) = self.initial_manifest?;
        Some((self.destination.as_ref()?.checkpoint_path()?, hash, bytes))
    }
    pub(super) fn initialize_export(
        &mut self,
        data_dir: &Path,
        snapshot: Snapshot,
    ) -> anyhow::Result<PathBuf> {
        let prepared = self.prepare_destination(data_dir, snapshot);
        let path = match prepared {
            Ok(path) => path,
            Err(error) => {
                self.export_error = true;
                let result = NativeExportResult {
                    status: NativeExportPublicationResult::NotPublished,
                    error: Some(error),
                    path: self
                        .destination
                        .as_ref()
                        .map(|destination| destination.path.clone()),
                    sha256: None,
                    bytes: 0,
                    boot_id: self.boot_id,
                    pid: self.pid,
                    starttime_ticks: self.starttime_ticks,
                    publication_serial: self.serial,
                    root_map_id: self.root_map_id,
                    final_export: false,
                    complete: false,
                    last_seq: self.last_seq,
                };
                result.record();
                return Err(result
                    .error
                    .context("Native export initialization failed")?);
            }
        };
        let result = self.export(false, snapshot);
        result.record();
        if let Some(error) = result.error {
            return Err(error);
        }
        ensure!(
            result.status == NativeExportPublicationResult::PublishedDurable,
            "Native initial manifest durability unconfirmed"
        );
        tracing::info!(native_publication_path = %path.display(), publication_serial = self.serial,
            root_map_id = self.root_map_id, "Native publication initial manifest ready");
        Ok(path)
    }
    fn prepare_destination(
        &mut self,
        data_dir: &Path,
        snapshot: Snapshot,
    ) -> anyhow::Result<PathBuf> {
        ensure!(
            self.destination.is_none() && self.root_map_id != 0 && !self.export_error,
            "Native export already initialized or root identity absent"
        );
        ensure!(
            self.hook_count == 0 && self.len == 1 && snapshot.epoch == 0 && !snapshot.terminal,
            "Native initial manifest must precede attachment and publication"
        );
        ensure!(
            !self.recording_error && !self.clock_error,
            "Native recording prerequisites failed"
        );
        let absolute = match bounded_directory_path(data_dir) {
            Ok(path) => path,
            Err(error) => {
                self.recording_error = true;
                return Err(error);
            }
        };
        // Match config_write's component walk; state_directory supplies its private-state policy and parent sync.
        let base = open_directory(&absolute)?;
        let state = crate::state::state_directory(&absolute, true, crate::state::private)?;
        let named_base = open_directory(&absolute)?;
        let before = base.metadata()?;
        let after = named_base.metadata()?;
        ensure!(
            (before.dev(), before.ino()) == (after.dev(), after.ino()),
            "Native data directory changed during preparation"
        );
        match mkdirat(&state, "native-publication", Mode::S_IRWXU) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(error) => return Err(error.into()),
        }
        let directory = File::from(openat(
            &state,
            "native-publication",
            directory_flags(),
            Mode::empty(),
        )?);
        check_private(&directory, true)?;
        state.sync_all()?;
        let name = format!(
            "{}-{}-{}.json",
            self.pid,
            self.starttime_ticks,
            self.identity()
        );
        let path = absolute.join("state/native-publication").join(&name);
        self.destination = Some(Destination {
            directory,
            path: path.clone(),
            name,
            installed: None,
        });
        Ok(path)
    }
    pub(super) fn export(&mut self, final_export: bool, snapshot: Snapshot) -> NativeExportResult {
        let mut result = NativeExportResult {
            status: NativeExportPublicationResult::NotPublished,
            error: None,
            path: self.destination.as_ref().map(|d| d.path.clone()),
            sha256: None,
            bytes: 0,
            boot_id: self.boot_id,
            pid: self.pid,
            starttime_ticks: self.starttime_ticks,
            publication_serial: self.identity(),
            root_map_id: self.root_map_id,
            final_export,
            complete: false,
            last_seq: self.last_seq,
        };
        let Some(mut buffer) = self.buffer.take() else {
            self.recording_error = true;
            self.export_error = true;
            result.error = Some(anyhow::anyhow!("Native export buffer absent"));
            return result;
        };
        let publication = self.publish(final_export, snapshot, &mut buffer, &mut result);
        self.buffer = Some(buffer);
        if let Err(error) = publication {
            self.export_error = true;
            result.complete = false;
            result.error = Some(error);
        }
        result
    }
    fn publish(
        &mut self,
        final_export: bool,
        snapshot: Snapshot,
        buffer: &mut [u8],
        result: &mut NativeExportResult,
    ) -> anyhow::Result<()> {
        ensure!(
            self.initial_manifest.is_some() || !self.export_error,
            "Native initial publication previously failed"
        );
        let destination = self
            .destination
            .as_ref()
            .context("Native export not initialized")?;
        destination.recheck()?;
        let mut temporary = Temporary::new(&destination.directory)?;
        let reasons = self.incomplete_reasons(final_export, snapshot);
        result.complete = reasons == 0;
        let (hash, bytes) = {
            let mut writer = Stream {
                file: &mut temporary.file,
                buffer,
                used: 0,
                bytes: 0,
                hash: Sha256::new(),
                #[cfg(test)]
                fail_write: self.fault == Some(ExportFault::Write),
                #[cfg(test)]
                short_write: self.fault == Some(ExportFault::ShortWrite),
            };
            serde_json::to_writer(
                &mut writer,
                &Projection {
                    recording: self,
                    snapshot,
                    final_export,
                    reasons,
                },
            )?;
            writer.flush()?;
            (Into::<[u8; 32]>::into(writer.hash.finalize()), writer.bytes)
        };
        #[cfg(test)]
        ensure!(
            self.fault != Some(ExportFault::FileSync),
            "injected Native file sync failure"
        );
        temporary.file.sync_all()?;
        if self.initial_manifest.is_none() {
            destination.checkpoint(
                &temporary,
                hash,
                bytes,
                buffer,
                #[cfg(test)]
                self.fault,
            )?;
        }
        destination.recheck()?;
        let installed = temporary.file.try_clone()?;
        #[cfg(test)]
        ensure!(
            self.fault != Some(ExportFault::Rename),
            "injected Native rename failure"
        );
        if destination.installed.is_some() {
            renameat(
                &destination.directory,
                temporary.name.as_str(),
                &destination.directory,
                destination.name.as_str(),
            )?;
        } else {
            crate::state::rename_noreplace(
                &destination.directory,
                temporary.name.as_str(),
                destination.name.as_str(),
            )?;
        }
        temporary.renamed = true;
        result.status = NativeExportPublicationResult::PublishedDurabilityUnknown;
        result.sha256 = Some(crate::configuration::encode_digest(&hash));
        result.bytes = bytes;
        self.destination
            .as_mut()
            .context("Native destination absent after rename")?
            .installed = Some(installed);
        #[cfg(test)]
        ensure!(
            self.fault != Some(ExportFault::DirectorySync),
            "injected Native directory sync failure after rename"
        );
        let destination = self
            .destination
            .as_ref()
            .context("Native destination absent after rename")?;
        destination.directory.sync_all()?;
        destination.recheck()?;
        if self.initial_manifest.is_none() {
            self.initial_manifest = Some((hash, bytes));
        }
        result.status = NativeExportPublicationResult::PublishedDurable;
        Ok(())
    }
    fn incomplete_reasons(&self, final_export: bool, snapshot: Snapshot) -> u32 {
        let mut reasons = 0;
        for (condition, bit) in [
            (!final_export, 0),
            (self.initial_manifest.is_none(), 1),
            (
                !self.completed || !snapshot.terminal || snapshot.epoch & 1 != 0,
                2,
            ),
            (!self.hooks_joined || !snapshot.hooks_joined, 3),
            (!snapshot.all_counters_sealed, 4),
            (self.overwritten_events != 0, 5),
            (self.recording_error, 6),
            (self.clock_error, 7),
            (self.accounting_error, 8),
            (self.counter_overflow, 9),
            (self.export_error, 10),
            (snapshot.failed, 11),
            (self.hook_count == 0, 12),
            (
                self.hooks[..self.hook_count]
                    .iter()
                    .any(|h| h.pending_new != 0),
                13,
            ),
            (!self.history_complete(snapshot), 14),
            (self.root_map_id == 0, 15),
        ] {
            if condition {
                reasons |= 1 << bit;
            }
        }
        reasons
    }
    fn history_complete(&self, snapshot: Snapshot) -> bool {
        if self.len == 0
            || self.overwritten_events != 0
            || self.total_appended != self.last_seq
            || self.last_seq != self.len as u64
        {
            return false;
        }
        let mut epoch = 0;
        let mut clock = self.collection_start.unwrap_or(0);
        for (index, event) in self.events().enumerate() {
            if event.seq != index as u64 + 1
                || validate_event(event).is_err()
                || !self.writer_event_valid(event, index)
                || event.outcome == NATIVE_OUTCOME_FAILED
            {
                return false;
            }
            if event.flags & NATIVE_EVENT_FLAG_TIMESTAMP_VALID != 0 {
                if event.boottime_after_ns < clock
                    || (event.boottime_before_ns != 0 && event.boottime_before_ns < clock)
                {
                    return false;
                }
                clock = event.boottime_after_ns;
            }
            let prior = |kind, operation| {
                self.events()
                    .take(index)
                    .rfind(move |e| e.kind == kind && e.operation_id == operation)
            };
            match event.kind {
                NATIVE_EVENT_INITIAL_STATE => {
                    if index != 0 || event.epoch_before != 0 || event.epoch_after != 0 {
                        return false;
                    }
                }
                NATIVE_EVENT_CLOSE_STORED | NATIVE_EVENT_REOPEN_STORED => {
                    let intent = if event.kind == NATIVE_EVENT_CLOSE_STORED {
                        NATIVE_EVENT_CLOSE_INTENT
                    } else {
                        NATIVE_EVENT_REOPEN_INTENT
                    };
                    let Some(before) = prior(intent, event.operation_id) else {
                        return false;
                    };
                    if before.epoch_before != event.epoch_before
                        || before.epoch_after != event.epoch_after
                        || event.related_seq != before.seq
                        || before.writer_id != event.writer_id
                        || event.epoch_before != epoch
                        || event.flags & NATIVE_EVENT_FLAG_TIMESTAMP_VALID == 0
                    {
                        return false;
                    }
                    if event.kind == NATIVE_EVENT_CLOSE_STORED {
                        if event.epoch_after & 1 != 0 || event.epoch_after <= epoch {
                            return false;
                        }
                        if !self.events().any(|e| {
                            e.kind == NATIVE_EVENT_CLOSE_DRAINED
                                && e.operation_id == event.operation_id
                                && e.related_seq == event.seq
                                && e.seq > event.seq
                        }) {
                            return false;
                        }
                    } else if event.epoch_before & 1 != 0
                        || event.epoch_after != epoch.checked_add(1).unwrap_or(0)
                        || event.epoch_after & 1 == 0
                        || self.events().take(index).any(|e| {
                            e.kind == NATIVE_EVENT_WRITER_OUTCOME
                                && e.outcome == NATIVE_OUTCOME_FAILED
                        })
                    {
                        return false;
                    }
                    if event.kind == NATIVE_EVENT_REOPEN_STORED
                        && self
                            .events()
                            .take(index)
                            .filter(|e| e.kind == NATIVE_EVENT_WRITER_BEGIN)
                            .any(|begin| {
                                !self.events().take(index).any(|e| {
                                    e.kind == NATIVE_EVENT_WRITER_OUTCOME
                                        && e.operation_id == begin.operation_id
                                        && e.writer_id == begin.writer_id
                                })
                            })
                    {
                        return false;
                    }
                    epoch = event.epoch_after;
                }
                NATIVE_EVENT_CLOSE_DRAINED => {
                    let Some(store) = self.events().take(index).find(|e| {
                        e.seq == event.related_seq
                            && matches!(
                                e.kind,
                                NATIVE_EVENT_CLOSE_STORED | NATIVE_EVENT_INITIAL_STATE
                            )
                    }) else {
                        return false;
                    };
                    if store.epoch_after != event.epoch_after
                        || event.flags & NATIVE_EVENT_FLAG_TIMESTAMP_VALID == 0
                        || event.outcome != NATIVE_OUTCOME_COMMITTED
                        || event.boottime_after_ns < store.boottime_after_ns
                    {
                        return false;
                    }
                }
                NATIVE_EVENT_WRITER_BEGIN => {
                    if prior(NATIVE_EVENT_WRITER_BEGIN, event.operation_id).is_some() {
                        return false;
                    }
                    if event.operation_id == 0
                        || event.writer_id == 0
                        || !self.events().any(|e| {
                            e.kind == NATIVE_EVENT_WRITER_OUTCOME
                                && e.operation_id == event.operation_id
                                && e.writer_id == event.writer_id
                                && e.seq > event.seq
                        })
                    {
                        return false;
                    }
                }
                NATIVE_EVENT_WRITER_OUTCOME => {
                    let Some(begin) = prior(NATIVE_EVENT_WRITER_BEGIN, event.operation_id) else {
                        return false;
                    };
                    if begin.writer_id != event.writer_id
                        || begin.reason != event.reason
                        || event.outcome == NATIVE_OUTCOME_PENDING
                        || prior(NATIVE_EVENT_WRITER_OUTCOME, event.operation_id).is_some()
                    {
                        return false;
                    }
                }
                NATIVE_EVENT_CLOSED_COUNTS_FINAL => {
                    if event.counter_epoch & 1 != 0
                        || event.flags & NATIVE_EVENT_FLAG_COUNTER_VALID == 0
                        || event.flags & NATIVE_EVENT_FLAG_COUNTER_OVERFLOW != 0
                        || !self.hooks[..self.hook_count]
                            .iter()
                            .any(|h| h.identity.hook_id == event.hook_id)
                    {
                        return false;
                    }
                    if !self.events().take(index).any(|e| {
                        (e.kind == NATIVE_EVENT_INITIAL_STATE
                            || e.kind == NATIVE_EVENT_CLOSE_STORED)
                            && e.epoch_after == event.counter_epoch
                            && e.seq == event.related_seq
                    }) {
                        return false;
                    }
                    if self.events().take(index).any(|e| {
                        e.kind == NATIVE_EVENT_CLOSED_COUNTS_FINAL
                            && e.hook_id == event.hook_id
                            && e.counter_epoch == event.counter_epoch
                    }) {
                        return false;
                    }
                }
                NATIVE_EVENT_CLOSE_INTENT | NATIVE_EVENT_REOPEN_INTENT => {
                    let stored = if event.kind == NATIVE_EVENT_CLOSE_INTENT {
                        NATIVE_EVENT_CLOSE_STORED
                    } else {
                        NATIVE_EVENT_REOPEN_STORED
                    };
                    if !self.events().any(|e| {
                        e.kind == stored && e.related_seq == event.seq && e.seq > event.seq
                    }) {
                        return false;
                    }
                }
                NATIVE_EVENT_TERMINAL_STATE => {
                    if event.epoch_after != epoch
                        || epoch & 1 != 0
                        || event.outcome != NATIVE_OUTCOME_COMMITTED
                        || !self.events().take(index).any(|e| {
                            e.kind == NATIVE_EVENT_CLOSE_DRAINED
                                && e.operation_id == event.operation_id
                                && e.epoch_after == epoch
                        })
                    {
                        return false;
                    }
                }
                NATIVE_EVENT_HOOK_REGISTERED => {
                    if epoch & 1 != 0
                        || !self.hooks[..self.hook_count].iter().any(|h| {
                            h.identity.hook_id == event.hook_id
                                && h.registered_seq == event.seq
                                && u64::from(h.identity.program_id) == event.counter_epoch
                        })
                    {
                        return false;
                    }
                }
                NATIVE_EVENT_PROGRAM_REPLACED => {
                    let Some(begin) = prior(NATIVE_EVENT_WRITER_BEGIN, event.operation_id) else {
                        return false;
                    };
                    if epoch & 1 != 0
                        || begin.writer_id != event.writer_id
                        || begin.reason != event.reason
                    {
                        return false;
                    }
                }
                NATIVE_EVENT_COLLECTION_END if index + 1 != self.len => {
                    return false;
                }
                _ => {}
            }
        }
        if epoch != snapshot.epoch {
            return false;
        }
        for hook in &self.hooks[..self.hook_count] {
            if hook.registered_seq == 0
                || !self.events().any(|e| {
                    e.seq == hook.registered_seq
                        && e.kind == NATIVE_EVENT_HOOK_REGISTERED
                        && e.hook_id == hook.identity.hook_id
                })
            {
                return false;
            }
            let mut program = hook.identity.program_id;
            let mut generation = hook.identity.attachment_generation;
            let mut pending: Option<&Event> = None;
            for event in self.events().filter(|e| {
                e.kind == NATIVE_EVENT_PROGRAM_REPLACED && e.hook_id == hook.identity.hook_id
            }) {
                if event.counter_value != u64::from(program)
                    || event.counter_epoch == 0
                    || event.counter_epoch > u64::from(u32::MAX)
                {
                    return false;
                }
                if event.outcome == NATIVE_OUTCOME_PENDING {
                    if pending.replace(event).is_some() {
                        return false;
                    }
                } else {
                    let Some(intent) = pending.take() else {
                        return false;
                    };
                    if event.outcome != NATIVE_OUTCOME_COMMITTED
                        || intent.counter_epoch != event.counter_epoch
                        || intent.operation_id != event.operation_id
                        || intent.writer_id != event.writer_id
                        || intent.reason != event.reason
                    {
                        return false;
                    }
                    program = event.counter_epoch as u32;
                    let Some(next) = generation.checked_add(1) else {
                        return false;
                    };
                    generation = next;
                }
            }
            if pending.is_some()
                || hook.current_program != program
                || hook.current_generation != generation
            {
                return false;
            }
            for boundary in self.events().filter(|e| {
                e.kind == NATIVE_EVENT_INITIAL_STATE || e.kind == NATIVE_EVENT_CLOSE_STORED
            }) {
                let replaced_before_registration = self.events().any(|e| {
                    e.kind == NATIVE_EVENT_CLOSE_STORED
                        && e.seq > boundary.seq
                        && e.seq < hook.registered_seq
                });
                if replaced_before_registration {
                    continue;
                }
                if !self.events().any(|e| {
                    e.kind == NATIVE_EVENT_CLOSED_COUNTS_FINAL
                        && e.hook_id == hook.identity.hook_id
                        && e.counter_epoch == boundary.epoch_after
                }) {
                    return false;
                }
            }
        }
        let Some(end) = self.events().last() else {
            return false;
        };
        end.kind == NATIVE_EVENT_COLLECTION_END
            && end.epoch_after == snapshot.epoch
            && end.flags & NATIVE_EVENT_FLAG_TIMESTAMP_VALID != 0
            && end.outcome == NATIVE_OUTCOME_COMMITTED
            && self.events().any(|e| {
                e.kind == NATIVE_EVENT_TERMINAL_STATE
                    && e.epoch_after == snapshot.epoch
                    && e.outcome == NATIVE_OUTCOME_COMMITTED
                    && e.seq < end.seq
            })
    }
}

fn validate_event(event: &Event) -> anyhow::Result<()> {
    ensure!(
        (NATIVE_EVENT_INITIAL_STATE..=NATIVE_EVENT_PROGRAM_REPLACED).contains(&event.kind),
        "unknown Native event kind"
    );
    ensure!(
        event.reason <= 14
            && (event.reason != 0
                || !matches!(
                    event.kind,
                    NATIVE_EVENT_WRITER_BEGIN | NATIVE_EVENT_WRITER_OUTCOME
                )),
        "unknown Native event reason"
    );
    ensure!(
        event.flags & !KNOWN_EVENT_FLAGS == 0 && event.reserved == [0; 24],
        "unsupported Native event flags or reserved bytes"
    );
    ensure!(
        event.outcome <= NATIVE_OUTCOME_FAILED,
        "unknown Native event outcome"
    );
    if matches!(
        event.kind,
        NATIVE_EVENT_CLOSE_STORED
            | NATIVE_EVENT_CLOSE_DRAINED
            | NATIVE_EVENT_REOPEN_STORED
            | NATIVE_EVENT_WRITER_OUTCOME
            | NATIVE_EVENT_CLOSED_COUNTS_FINAL
            | NATIVE_EVENT_TERMINAL_STATE
            | NATIVE_EVENT_COLLECTION_END
    ) {
        ensure!(
            event.outcome != NATIVE_OUTCOME_PENDING,
            "settled Native event has pending outcome"
        );
    }
    if matches!(
        event.kind,
        NATIVE_EVENT_HOOK_REGISTERED
            | NATIVE_EVENT_CLOSED_COUNTS_FINAL
            | NATIVE_EVENT_PROGRAM_REPLACED
    ) {
        ensure!(event.hook_id != 0, "Native hook identity absent");
    }
    if matches!(
        event.kind,
        NATIVE_EVENT_WRITER_BEGIN | NATIVE_EVENT_WRITER_OUTCOME | NATIVE_EVENT_PROGRAM_REPLACED
    ) {
        ensure!(
            event.operation_id != 0 && event.writer_id != 0 && event.reason != 0,
            "Native writer identity or reason absent"
        );
    }
    if event.flags & NATIVE_EVENT_FLAG_TIMESTAMP_VALID != 0 {
        ensure!(
            event.boottime_before_ns <= event.boottime_after_ns,
            "reversed Native timestamp bracket"
        );
    }
    Ok(())
}

fn process_identity() -> anyhow::Result<([u8; 36], u32, u64)> {
    let mut boot = [0u8; 37];
    let mut file = File::open("/proc/sys/kernel/random/boot_id")?;
    file.read_exact(&mut boot)?;
    let mut extra = [0];
    ensure!(
        file.read(&mut extra)? == 0 && boot[36] == b'\n',
        "unexpected boot ID length"
    );
    ensure!(
        boot[..36]
            .iter()
            .enumerate()
            .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }),
        "invalid boot ID"
    );
    let mut stat = [0u8; 4096];
    let mut file = File::open("/proc/self/stat")?;
    let mut used = 0;
    while used < stat.len() {
        let count = file.read(&mut stat[used..])?;
        if count == 0 {
            break;
        }
        used += count;
    }
    ensure!(used < stat.len(), "process stat exceeds identity bound");
    let stat = std::str::from_utf8(&stat[..used])?;
    let starttime = stat
        .rsplit_once(')')
        .and_then(|(_, fields)| fields.split_ascii_whitespace().nth(19))
        .context("process stat missing starttime")?
        .parse::<u64>()?;
    ensure!(starttime != 0, "process starttime absent");
    let mut boot_id = [0; 36];
    boot_id.copy_from_slice(&boot[..36]);
    Ok((boot_id, std::process::id(), starttime))
}
fn bounded_directory_path(path: &Path) -> anyhow::Result<PathBuf> {
    ensure!(
        path.as_os_str().len() <= 1024,
        "Native data directory path exceeds data_dir_path_max_bytes=1024"
    );
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    let mut cwd = [0u8; 1025];
    // getcwd refuses an overlong working directory before allocating any path storage.
    if unsafe { libc::getcwd(cwd.as_mut_ptr().cast(), cwd.len()) }.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let cwd = std::ffi::CStr::from_bytes_until_nul(&cwd)?.to_bytes();
    let combined = cwd
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(path.as_os_str().len()));
    ensure!(
        combined.is_some_and(|n| n <= 1024),
        "Native relative data directory exceeds data_dir_path_max_bytes=1024"
    );
    Ok(Path::new(std::ffi::OsStr::from_bytes(cwd)).join(path))
}
fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}
fn open_directory(path: &Path) -> anyhow::Result<File> {
    ensure!(path.is_absolute(), "Native directory must be absolute");
    let mut directory = File::from(open("/", directory_flags(), Mode::empty())?);
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = File::from(openat(&directory, name, directory_flags(), Mode::empty())?)
            }
            _ => anyhow::bail!("unsafe Native directory component"),
        }
    }
    Ok(directory)
}
fn check_private(file: &File, directory: bool) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.uid() == crate::state::effective_uid()
            && metadata.mode() & 0o077 == 0
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file() && metadata.mode() & 0o777 == 0o600 && metadata.nlink() == 1
            },
        "unsafe Native artifact ownership, mode or file type"
    );
    #[cfg(not(test))]
    ensure!(
        metadata.uid() == 0,
        "Native publication artifact requires root ownership"
    );
    Ok(())
}
fn recheck_directory(directory: &File, path: &Path) -> anyhow::Result<()> {
    check_private(directory, true)?;
    let current = open_directory(path)?;
    let old = directory.metadata()?;
    let now = current.metadata()?;
    ensure!(
        (old.dev(), old.ino()) == (now.dev(), now.ino()),
        "Native artifact directory changed"
    );
    Ok(())
}
impl Destination {
    fn recheck(&self) -> anyhow::Result<()> {
        recheck_directory(
            &self.directory,
            self.path
                .parent()
                .context("Native destination parent absent")?,
        )?;
        if let Some(installed) = &self.installed {
            check_private(installed, false)?;
            let named = fstatat(
                &self.directory,
                self.name.as_str(),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )?;
            let held = installed.metadata()?;
            ensure!(
                named.st_mode & libc::S_IFMT == libc::S_IFREG
                    && (named.st_dev, named.st_ino) == (held.dev(), held.ino()),
                "Native artifact replaced externally"
            );
        }
        Ok(())
    }
    fn checkpoint_path(&self) -> Option<PathBuf> {
        Some(
            self.path
                .parent()?
                .with_file_name("native-publication-initial")
                .join(&self.name),
        )
    }
    fn checkpoint(
        &self,
        original: &Temporary,
        hash: [u8; 32],
        bytes: u64,
        buffer: &mut [u8],
        #[cfg(test)] fault: Option<ExportFault>,
    ) -> anyhow::Result<()> {
        let path = self
            .checkpoint_path()
            .context("Native checkpoint path absent")?;
        let parent = path.parent().context("Native checkpoint parent absent")?;
        let directory = {
            let state = open_directory(parent.parent().context("Native state path absent")?)?;
            check_private(&state, true)?;
            match mkdirat(&state, "native-publication-initial", Mode::S_IRWXU) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(error) => return Err(error.into()),
            }
            let directory = File::from(openat(
                &state,
                "native-publication-initial",
                directory_flags(),
                Mode::empty(),
            )?);
            check_private(&directory, true)?;
            #[cfg(test)]
            ensure!(
                fault != Some(ExportFault::CheckpointParentSync),
                "injected Native checkpoint parent sync failure"
            );
            // EEXIST can follow another creator or an earlier failed parent sync.
            state.sync_all()?;
            directory
        };
        recheck_directory(&directory, parent)?;
        let mut checkpoint = Temporary::new(&directory)?;
        drop(directory);
        let mut source = File::from(openat(
            &original.directory,
            original.name.as_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        original.recheck_source(&source, bytes)?;
        let before = source.metadata()?;
        let mut copied = 0u64;
        let mut copied_hash = Sha256::new();
        while copied < bytes {
            let take = (bytes - copied).min(buffer.len() as u64) as usize;
            let count = source.read(&mut buffer[..take])?;
            ensure!(count != 0, "Native checkpoint source truncated during copy");
            #[cfg(test)]
            ensure!(
                fault != Some(ExportFault::CheckpointWrite),
                "injected Native checkpoint write failure"
            );
            checkpoint.file.write_all(&buffer[..count])?;
            copied_hash.update(&buffer[..count]);
            copied += count as u64;
        }
        ensure!(
            copied == bytes && <[u8; 32]>::from(copied_hash.finalize()) == hash,
            "Native checkpoint digest or length differs from completed export"
        );
        #[cfg(test)]
        if fault == Some(ExportFault::CheckpointSourceChanged) {
            original.file.set_len(0)?;
        }
        original.recheck_source(&source, bytes)?;
        let after = source.metadata()?;
        ensure!(
            (
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ) == (
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            ),
            "Native checkpoint source modified during copy"
        );
        drop(source);
        #[cfg(test)]
        ensure!(
            fault != Some(ExportFault::CheckpointFileSync),
            "injected Native checkpoint file sync failure"
        );
        checkpoint.file.sync_all()?;
        crate::state::rename_noreplace(
            &checkpoint.directory,
            checkpoint.name.as_str(),
            self.name.as_str(),
        )?;
        checkpoint.renamed = true;
        #[cfg(test)]
        ensure!(
            fault != Some(ExportFault::CheckpointDirectorySync),
            "injected Native checkpoint directory sync failure"
        );
        checkpoint.directory.sync_all()?;
        recheck_directory(&checkpoint.directory, parent)?;
        check_private(&checkpoint.file, false)?;
        let held = checkpoint.file.metadata()?;
        let named = fstatat(
            &checkpoint.directory,
            self.name.as_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        ensure!(
            held.len() == bytes
                && named.st_mode & libc::S_IFMT == libc::S_IFREG
                && (named.st_dev, named.st_ino) == (held.dev(), held.ino()),
            "Native installed checkpoint changed"
        );
        Ok(())
    }
}
struct Temporary {
    directory: File,
    name: String,
    file: File,
    renamed: bool,
}
impl Temporary {
    fn new(directory: &File) -> anyhow::Result<Self> {
        let directory = directory.try_clone()?;
        let name = format!(".native-publication-{}.tmp", uuid::Uuid::new_v4());
        let file = File::from(openat(
            &directory,
            name.as_str(),
            OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_NOFOLLOW
                | OFlag::O_NONBLOCK
                | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?);
        let temporary = Self {
            directory,
            name,
            file,
            renamed: false,
        };
        check_private(&temporary.file, false)?;
        Ok(temporary)
    }
    fn recheck_source(&self, source: &File, bytes: u64) -> anyhow::Result<()> {
        check_private(&self.file, false)?;
        check_private(source, false)?;
        let original = self.file.metadata()?;
        let held = source.metadata()?;
        let named = fstatat(
            &self.directory,
            self.name.as_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        ensure!(
            original.len() == bytes
                && held.len() == bytes
                && named.st_mode & libc::S_IFMT == libc::S_IFREG
                && (original.dev(), original.ino()) == (held.dev(), held.ino())
                && (named.st_dev, named.st_ino) == (held.dev(), held.ino()),
            "Native checkpoint source identity or length changed"
        );
        Ok(())
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.renamed {
            let _ = unlinkat(
                &self.directory,
                self.name.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
        }
    }
}
struct Stream<'a> {
    file: &'a mut File,
    buffer: &'a mut [u8],
    used: usize,
    bytes: u64,
    hash: Sha256,
    #[cfg(test)]
    fail_write: bool,
    #[cfg(test)]
    short_write: bool,
}
impl Write for Stream<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        if self.fail_write {
            return Err(io::Error::other("injected Native write failure"));
        }
        let count = bytes.len();
        while !bytes.is_empty() {
            if self.used == self.buffer.len() {
                self.flush()?;
            }
            let take = bytes.len().min(self.buffer.len() - self.used);
            self.buffer[self.used..self.used + take].copy_from_slice(&bytes[..take]);
            self.used += take;
            bytes = &bytes[take..];
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if self.short_write && self.used != 0 {
            self.file.write_all(&self.buffer[..self.used / 2])?;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "injected Native short write before rename",
            ));
        }
        self.file.write_all(&self.buffer[..self.used])?;
        self.hash.update(&self.buffer[..self.used]);
        self.bytes = self
            .bytes
            .checked_add(self.used as u64)
            .ok_or_else(|| io::Error::other("Native export byte count overflow"))?;
        self.used = 0;
        Ok(())
    }
}
struct CapturedReceipts<'a>(&'a Recording);
impl Serialize for CapturedReceipts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let r = self.0;
        let mut seq = serializer.serialize_seq(Some(r.captured_len))?;
        for offset in 0..r.captured_len {
            seq.serialize_element(
                &r.captured_ring[(r.captured_head + offset) % CAPTURED_CAPACITY],
            )?;
        }
        seq.end()
    }
}
impl Serialize for CapturedReceipt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer
            .serialize_struct("CapturedReceipt", 35 + usize::from(self.outcome.is_some()))?;
        macro_rules! decimal {
            ($($field:ident),+ $(,)?) => {$(
                out.serialize_field(stringify!($field), &self.$field.map(Decimal))?;
            )+};
        }
        out.serialize_field("seq", &Decimal(self.seq))?;
        out.serialize_field("kind", &self.kind)?;
        out.serialize_field("key", &self.key.as_ref().map(CapturedKey))?;
        decimal!(
            claim_epoch,
            claim_incarnation,
            claim_scope,
            producer_epoch,
            producer_incarnation,
            producer_expires_boottime_ns,
            basis_epoch,
            routing_generation,
            mode_revision,
            fact_scope,
            fact_revision,
            fact_horizon,
            return_attachment,
            slot,
            op_incarnation,
            entry_seq,
            boottime_ns,
            related_seq,
            inventory_held,
            inventory_pending,
            inventory_flight,
            count_before,
            count_after
        );
        out.serialize_field("producer_flags", &self.producer_flags)?;
        out.serialize_field("basis_flags", &self.basis_flags)?;
        out.serialize_field("phase_after", &self.phase_after)?;
        out.serialize_field("terminal", &self.terminal)?;
        out.serialize_field("routing_fingerprint", &self.routing_fingerprint)?;
        out.serialize_field(
            "completion_handle",
            &self.completion_handle.map(|v| v.map(Decimal)),
        )?;
        out.serialize_field("joined_receipt_file", &self.joined_receipt_file)?;
        out.serialize_field("terminal_inventory_sha256", &self.terminal_inventory_sha256)?;
        if let Some(outcome) = self.outcome {
            out.serialize_field("outcome", outcome)?;
        }
        out.serialize_field("fresh_grace", &self.fresh_grace)?;
        out.end()
    }
}
impl Serialize for CapturedJoinedReceiptFile {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(
            std::str::from_utf8(&self.bytes[..usize::from(self.len)])
                .map_err(serde::ser::Error::custom)?,
        )
    }
}
struct CapturedRealmInventory<'a>(&'a Recording);
impl Serialize for CapturedRealmInventory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Some(inventory) = self.0.captured_inventory else {
            return serializer.serialize_none();
        };
        let mut out = serializer.serialize_struct("CapturedRealmInventory", 5)?;
        out.serialize_field("return_attachment", &Decimal(inventory.return_attachment))?;
        out.serialize_field("inventory_seq", &Decimal(inventory.inventory_seq))?;
        out.serialize_field("boottime_ns", &Decimal(inventory.boottime_ns))?;
        out.serialize_field("status", &inventory.status)?;
        out.serialize_field("candidates", &self.0.captured_realms[..inventory.len])?;
        out.end()
    }
}
impl Serialize for CapturedRealm {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("CapturedRealm", 6)?;
        out.serialize_field("role", "canonical_tap_gate")?;
        out.serialize_field(
            "pin_path",
            std::str::from_utf8(&self.pin_path[..usize::from(self.pin_path_len)])
                .map_err(serde::ser::Error::custom)?,
        )?;
        out.serialize_field("program_id", &self.program_id)?;
        out.serialize_field("realm_index", &self.realm_index)?;
        out.serialize_field("closed_epoch", &Decimal(self.closed_epoch))?;
        out.serialize_field("state", &self.state)?;
        out.end()
    }
}
struct CapturedKey<'a>(&'a NativeKey);
impl Serialize for CapturedKey<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let key = self.0;
        let mut out = serializer.serialize_struct("NativeKeyV2", 12)?;
        macro_rules! field {
            ($($field:ident),+ $(,)?) => {$(
                out.serialize_field(stringify!($field), &key.$field)?;
            )+};
        }
        field!(
            src_ip, dst_ip, src_port, dst_port, l4proto, ip_version, domain, direction
        );
        out.serialize_field("namespace_cookie", &Decimal(key.namespace_cookie))?;
        field!(zone, zone_state, reserved);
        out.end()
    }
}
struct Decimal(u64);
impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut digits = [b'0'; 20];
        let mut value = self.0;
        let mut start = 19;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        while value != 0 {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        serializer.serialize_str(
            std::str::from_utf8(&digits[start..]).map_err(serde::ser::Error::custom)?,
        )
    }
}
struct Projection<'a> {
    recording: &'a Recording,
    snapshot: Snapshot,
    final_export: bool,
    reasons: u32,
}
impl Serialize for Projection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let r = self.recording;
        let s = self.snapshot;
        let mut out = serializer.serialize_struct("NativePublication", 45)?;
        macro_rules! field {
            ($name:literal, $value:expr) => {
                out.serialize_field($name, &$value)?;
            };
        }
        field!("schema", SCHEMA);
        field!("clock_id", "CLOCK_BOOTTIME");
        field!("unit", "ns");
        field!(
            "boot_id",
            std::str::from_utf8(&r.boot_id).map_err(serde::ser::Error::custom)?
        );
        field!("pid", r.pid);
        field!("starttime_ticks", Decimal(r.starttime_ticks));
        field!("publication_serial", Decimal(r.serial));
        field!("root_map_id", r.root_map_id);
        field!("build_version", crate::VERSION);
        field!("source_sha", env!("HONK_SOURCE_SHA"));
        field!("collection_start_ns", r.collection_start.map(Decimal));
        field!(
            "collection_end_ns",
            r.events()
                .last()
                .filter(|e| e.kind == NATIVE_EVENT_COLLECTION_END
                    && e.flags & NATIVE_EVENT_FLAG_TIMESTAMP_VALID != 0)
                .map(|e| Decimal(e.boottime_after_ns))
        );
        field!("initial_epoch", Decimal(0));
        field!("initial_flags", 0u32);
        field!("final_epoch", Decimal(s.epoch));
        field!("final_flags", s.flags);
        field!("ready", s.ready);
        field!("capture_ready", s.capture_ready);
        field!("failed", s.failed);
        field!("terminal", s.terminal);
        field!("hooks_joined", s.hooks_joined && r.hooks_joined);
        field!("all_counters_sealed", s.all_counters_sealed);
        field!("final", self.final_export);
        field!("complete", self.reasons == 0);
        field!("incomplete_reasons", Reasons(self.reasons));
        // Directory durability occurs after these bytes exist; only the separately retained result can attest it.
        field!(
            "durability_evidence",
            "REQUIRES_MATCHING_EXTERNAL_PUBLISHED_DURABLE_RESULT"
        );
        field!("ring_capacity", r.ring.len());
        field!("hook_capacity", MAX_HOOKS);
        field!("max_targets", MAX_HOOKS / 2);
        field!("max_hooks", MAX_HOOKS);
        field!("data_dir_path_max_bytes", 1024usize);
        field!(
            "first_retained_seq",
            Decimal(r.events().next().map_or(0, |e| e.seq))
        );
        field!("last_seq", Decimal(r.last_seq));
        field!("total_appended", Decimal(r.total_appended));
        field!("overwritten_events", Decimal(r.overwritten_events));
        field!("recording_error", r.recording_error);
        field!("clock_error", r.clock_error);
        field!("accounting_error", r.accounting_error);
        field!("counter_overflow", r.counter_overflow);
        field!("export_error", r.export_error);
        field!("hooks", Hooks(r));
        field!("events", Events(r));
        field!("captured_receipts", CapturedReceipts(r));
        field!(
            "captured_receipts_evicted",
            Decimal(r.captured_receipts_evicted)
        );
        field!("captured_realm_inventory", CapturedRealmInventory(r));
        out.end()
    }
}
const REASONS: [&str; 16] = [
    "PARTIAL_EXPORT",
    "MISSING_INITIAL_MANIFEST",
    "MISSING_TERMINAL_CLOSURE",
    "HOOKS_NOT_JOINED",
    "UNSEALED_COUNTERS",
    "HISTORY_OVERWRITTEN",
    "RECORDING_ERROR",
    "CLOCK_ERROR",
    "ACCOUNTING_ERROR",
    "COUNTER_OVERFLOW",
    "PRIOR_EXPORT_ERROR",
    "PUBLICATION_FAILED",
    "MISSING_HOOK_IDENTITIES",
    "UNSETTLED_PROGRAM_REPLACEMENT",
    "INCOMPLETE_HISTORY",
    "MISSING_ROOT_IDENTITY",
];
struct Reasons(u32);
impl Serialize for Reasons {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.count_ones() as usize))?;
        for (bit, reason) in REASONS.iter().enumerate() {
            if self.0 & (1 << bit) != 0 {
                seq.serialize_element(reason)?;
            }
        }
        seq.end()
    }
}
struct Hooks<'a>(&'a Recording);
impl Serialize for Hooks<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.hook_count))?;
        for hook in &self.0.hooks[..self.0.hook_count] {
            seq.serialize_element(&HookProjection(hook, self.0.serial))?;
        }
        seq.end()
    }
}
struct HookProjection<'a>(&'a Hook, u64);
impl Serialize for HookProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let h = self.0.identity;
        let mut out = serializer.serialize_struct("NativeHook", 13)?;
        out.serialize_field("hook_id", &Decimal(h.hook_id))?;
        out.serialize_field("target_serial", &Decimal(h.target_serial))?;
        out.serialize_field("kind", &h.kind)?;
        out.serialize_field("scope", &Decimal(h.scope))?;
        out.serialize_field("namespace_cookie", &Decimal(h.namespace_cookie))?;
        out.serialize_field("ifindex", &h.ifindex)?;
        out.serialize_field("attachment_generation", &Decimal(h.attachment_generation))?;
        out.serialize_field("counter_map_id", &h.counter_map_id)?;
        out.serialize_field("initial_program_id", &h.program_id)?;
        out.serialize_field("current_program_id", &self.0.current_program)?;
        out.serialize_field("registered_seq", &Decimal(self.0.registered_seq))?;
        out.serialize_field("publication_serial", &Decimal(self.1))?;
        out.serialize_field(
            "current_attachment_generation",
            &Decimal(self.0.current_generation),
        )?;
        out.end()
    }
}
struct Events<'a>(&'a Recording);
impl Serialize for Events<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len))?;
        for event in self.0.events() {
            seq.serialize_element(&EventProjection(event))?;
        }
        seq.end()
    }
}
struct EventProjection<'a>(&'a Event);
impl Serialize for EventProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let e = self.0;
        let mut out = serializer.serialize_struct("NativeEventV1", 19)?;
        macro_rules! decimal {
            ($field:ident) => {
                out.serialize_field(stringify!($field), &Decimal(e.$field))?;
            };
        }
        decimal!(seq);
        decimal!(operation_id);
        decimal!(writer_id);
        decimal!(epoch_before);
        decimal!(epoch_after);
        decimal!(boottime_before_ns);
        decimal!(boottime_after_ns);
        decimal!(related_seq);
        decimal!(counter_epoch);
        decimal!(counter_value);
        decimal!(hook_id);
        out.serialize_field("outcome", &e.outcome)?;
        out.serialize_field("kind", &e.kind)?;
        out.serialize_field("reason", &e.reason)?;
        out.serialize_field("flags", &e.flags)?;
        out.serialize_field("reserved", &e.reserved)?;
        let replacement = e.kind == NATIVE_EVENT_PROGRAM_REPLACED;
        out.serialize_field(
            "old_program_id",
            &replacement.then_some(Decimal(e.counter_value)),
        )?;
        out.serialize_field(
            "new_program_id",
            &replacement.then_some(Decimal(e.counter_epoch)),
        )?;
        out.serialize_field("version", &1u32)?;
        out.end()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExportFault {
    Write,
    ShortWrite,
    FileSync,
    Rename,
    DirectorySync,
    CheckpointParentSync,
    CheckpointWrite,
    CheckpointSourceChanged,
    CheckpointFileSync,
    CheckpointDirectorySync,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::os::unix::fs::{
        DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink,
    };

    fn recording() -> Recording {
        Recording::test_new(&MemoryBudget::new(1 << 20)).unwrap()
    }
    #[test]
    fn captured_receipts_reserve_before_allocation_and_evict_without_growth() {
        let base = 32 * size_of::<Event>()
            + OWNER_BYTES
            + 4096
            + CAPTURED_REALM_CAPACITY * size_of::<CapturedRealm>();
        let required = base + CAPTURED_CAPACITY * size_of::<CapturedReceipt>();
        let short = MemoryBudget::new(required - 1);
        assert!(Recording::test_new(&short).is_err());
        assert_eq!(short.used(), 0);
        let budget = MemoryBudget::new(required);
        let mut r = Recording::test_new(&budget).unwrap();
        let storage = r.captured_ring.as_ptr();
        let capacity = r.captured_ring.capacity();
        for n in 1..=CAPTURED_CAPACITY + 2 {
            assert_eq!(
                r.captured(CapturedReceipt {
                    kind: "OPERATION_PREPARED",
                    claim_epoch: Some(n as u64),
                    ..CapturedReceipt::default()
                }),
                n as u64
            );
        }
        assert_eq!(r.captured_len, CAPTURED_CAPACITY);
        assert_eq!(r.captured_receipts_evicted, 2);
        assert_eq!(r.captured_ring.as_ptr(), storage);
        assert_eq!(r.captured_ring.capacity(), capacity);
        assert_eq!(budget.used(), required);
        let value = serde_json::to_value(Projection {
            recording: &r,
            snapshot: Snapshot::default(),
            final_export: false,
            reasons: 1,
        })
        .unwrap();
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["captured_receipts_evicted"], "2");
        let receipts = value["captured_receipts"].as_array().unwrap();
        assert_eq!(receipts.len(), CAPTURED_CAPACITY);
        assert_eq!(receipts[0]["seq"], "3");
        assert_eq!(receipts[CAPTURED_CAPACITY - 1]["seq"], "258");
        drop(r);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn captured_receipts_preserve_absence_and_exact_scalar_identity() {
        let value = serde_json::to_value(CapturedReceipt::default()).unwrap();
        assert!(value.get("outcome").is_none());
        for (field, value) in value.as_object().unwrap() {
            if field != "kind" && field != "seq" {
                assert!(value.is_null(), "{field} invented unavailable evidence");
            }
        }
        let key = NativeKey {
            namespace_cookie: u64::MAX,
            ..NativeKey::default()
        };
        let value = serde_json::to_value(CapturedReceipt {
            key: Some(key),
            claim_epoch: Some(u64::MAX),
            routing_fingerprint: Some([255; 32]),
            completion_handle: Some([u64::MAX, 0, 1, 2]),
            outcome: Some("Transferred"),
            inventory_held: Some(u64::MAX),
            inventory_pending: Some(0),
            inventory_flight: Some(1),
            count_before: Some(2),
            count_after: Some(3),
            phase_after: Some(5),
            terminal: Some(true),
            entry_seq: Some(7),
            fresh_grace: Some(true),
            ..CapturedReceipt::default()
        })
        .unwrap();
        assert_eq!(value["key"]["namespace_cookie"], u64::MAX.to_string());
        assert_eq!(value["claim_epoch"], u64::MAX.to_string());
        assert_eq!(value["completion_handle"][0], u64::MAX.to_string());
        assert_eq!(value["completion_handle"][1], "0");
        assert_eq!(
            value["routing_fingerprint"],
            serde_json::to_value([255u8; 32]).unwrap()
        );
        assert_eq!(value["key"]["reserved"], serde_json::json!([0, 0, 0, 0, 0]));
        assert_eq!(value["entry_seq"], "7");
        assert_eq!(value["fresh_grace"], true);
        assert_eq!(value["outcome"], "Transferred");
        assert_eq!(value["inventory_held"], u64::MAX.to_string());
        assert_eq!(value["inventory_pending"], "0");
        assert_eq!(value["inventory_flight"], "1");
        assert_eq!(value["count_before"], "2");
        assert_eq!(value["count_after"], "3");
        assert_eq!(value["phase_after"], 5);
        assert_eq!(value["terminal"], true);
        let online = serde_json::to_value(CapturedReceipt {
            terminal: Some(false),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(online["terminal"], false);
    }
    #[test]
    fn captured_joined_ack_preserves_exact_file_digest_and_precharged_ring() {
        let budget = MemoryBudget::new(1 << 20);
        let mut r = Recording::test_new(&budget).unwrap();
        let reserved = budget.used();
        let storage = r.captured_ring.as_ptr();
        let filename = format!("旧\"{}", "x".repeat(251));
        assert_eq!(filename.len(), 255);
        let digest = std::array::from_fn(|i| i as u8);
        assert_eq!(
            r.captured_joined_ack(u64::MAX, &filename, digest).unwrap(),
            1
        );
        let value = serde_json::to_value(CapturedReceipts(&r)).unwrap();
        assert_eq!(value[0]["kind"], "CAPTURED_JOINED_ACK");
        assert_eq!(value[0]["return_attachment"], u64::MAX.to_string());
        assert_eq!(value[0]["joined_receipt_file"], filename);
        assert_eq!(
            value[0]["terminal_inventory_sha256"],
            serde_json::to_value(digest).unwrap()
        );
        assert!(value[0].get("outcome").is_none());
        let too_long = "x".repeat(256);
        for invalid in [
            "",
            ".",
            "..",
            "../joined",
            "/joined",
            "joined\0file",
            &too_long,
        ] {
            assert!(r.captured_joined_ack(7, invalid, [255; 32]).is_err());
            assert_eq!(r.captured_last_seq, 1);
            assert_eq!(serde_json::to_value(CapturedReceipts(&r)).unwrap(), value);
        }
        assert!(r.accounting_error && r.recording_error);
        assert_eq!(r.captured_ring.as_ptr(), storage);
        assert_eq!(budget.used(), reserved);
        drop(r);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn captured_inventory_serializes_actual_candidates_and_latest_empty_inventory() {
        let mut r = recording();
        assert!(
            serde_json::to_value(CapturedRealmInventory(&r))
                .unwrap()
                .is_null()
        );
        let path = format!("/{}", "x".repeat(CAPTURED_PIN_PATH_BYTES - 1));
        let installed = CapturedRealmCandidate {
            pin_path: Path::new(&path),
            program_id: u32::MAX,
            realm_index: u32::MAX,
            closed_epoch: u64::MAX,
            state: CapturedRealmState::Installed,
        };
        let retired = CapturedRealmCandidate {
            pin_path: Path::new("/actual/pin-旧\""),
            program_id: 2,
            realm_index: 3,
            closed_epoch: 4,
            state: CapturedRealmState::RetiredPending,
        };
        r.captured_inventory(
            u64::MAX,
            CapturedInventoryStatus::Committed,
            [installed, retired].into_iter(),
        )
        .unwrap();
        let value = serde_json::to_value(Projection {
            recording: &r,
            snapshot: Snapshot::default(),
            final_export: false,
            reasons: 1,
        })
        .unwrap();
        let inventory = &value["captured_realm_inventory"];
        assert_eq!(inventory["return_attachment"], u64::MAX.to_string());
        assert_eq!(inventory["inventory_seq"], "1");
        assert_eq!(inventory["status"], "Committed");
        assert_eq!(
            decimal(&inventory["boottime_ns"]).unwrap(),
            r.captured_inventory.unwrap().boottime_ns
        );
        assert_eq!(inventory["candidates"].as_array().unwrap().len(), 2);
        assert_eq!(
            inventory["candidates"][0],
            serde_json::json!({
                "role": "canonical_tap_gate", "pin_path": path, "program_id": u32::MAX,
                "realm_index": u32::MAX, "closed_epoch": u64::MAX.to_string(), "state": "Installed",
            })
        );
        assert_eq!(
            inventory["candidates"][1],
            serde_json::json!({
                "role": "canonical_tap_gate", "pin_path": "/actual/pin-旧\"", "program_id": 2,
                "realm_index": 3, "closed_epoch": "4", "state": "retired-pending",
            })
        );
        r.captured_inventory(
            u64::MAX,
            CapturedInventoryStatus::Partial,
            std::iter::once(retired),
        )
        .unwrap();
        let value = serde_json::to_value(CapturedRealmInventory(&r)).unwrap();
        assert_eq!(value["inventory_seq"], "2");
        assert_eq!(value["status"], "Partial");
        assert_eq!(value["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(value["candidates"][0]["program_id"], 2);
        r.captured_inventory(
            u64::MAX,
            CapturedInventoryStatus::Failed,
            std::iter::empty(),
        )
        .unwrap();
        let value = serde_json::to_value(CapturedRealmInventory(&r)).unwrap();
        assert_eq!(value["inventory_seq"], "3");
        assert_eq!(value["status"], "Failed");
        assert_eq!(value["return_attachment"], u64::MAX.to_string());
        assert_eq!(value["candidates"], serde_json::json!([]));
        assert!(!r.accounting_error && !r.recording_error);
    }

    #[test]
    fn captured_inventory_rejects_partial_replacements_and_closes_accounting() {
        let mut r = recording();
        let retained = CapturedRealmCandidate {
            pin_path: Path::new("/actual/retained"),
            program_id: 7,
            realm_index: 8,
            closed_epoch: 9,
            state: CapturedRealmState::RetiredPending,
        };
        r.captured_inventory(
            10,
            CapturedInventoryStatus::Committed,
            std::iter::once(retained),
        )
        .unwrap();
        let before = serde_json::to_value(CapturedRealmInventory(&r)).unwrap();
        let changed = CapturedRealmCandidate {
            program_id: 11,
            ..retained
        };
        let error = r
            .captured_inventory(
                10,
                CapturedInventoryStatus::Partial,
                std::iter::repeat_n(changed, CAPTURED_REALM_CAPACITY + 1),
            )
            .unwrap_err();
        assert!(error.to_string().contains("capacity"));
        assert_eq!(
            serde_json::to_value(CapturedRealmInventory(&r)).unwrap(),
            before
        );
        assert!(r.accounting_error && r.recording_error);
        let too_long = "x".repeat(CAPTURED_PIN_PATH_BYTES + 1);
        for path in [
            Path::new(&too_long),
            Path::new(""),
            Path::new("/invalid\0pin"),
            Path::new(std::ffi::OsStr::from_bytes(b"/invalid\xff")),
        ] {
            let invalid = CapturedRealmCandidate {
                pin_path: path,
                ..changed
            };
            assert!(
                r.captured_inventory(
                    10,
                    CapturedInventoryStatus::Partial,
                    [changed, invalid].into_iter()
                )
                .is_err()
            );
            assert_eq!(
                serde_json::to_value(CapturedRealmInventory(&r)).unwrap(),
                before
            );
        }
        r.fail_clock_for_test(true);
        assert!(
            r.captured_inventory(
                10,
                CapturedInventoryStatus::Partial,
                std::iter::once(changed)
            )
            .is_err()
        );
        assert!(r.clock_error);
        assert_eq!(
            serde_json::to_value(CapturedRealmInventory(&r)).unwrap(),
            before
        );
        r.fail_clock_for_test(false);
        r.captured_inventory.as_mut().unwrap().inventory_seq = u64::MAX;
        let before = serde_json::to_value(CapturedRealmInventory(&r)).unwrap();
        assert!(
            r.captured_inventory(10, CapturedInventoryStatus::Failed, std::iter::empty())
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(CapturedRealmInventory(&r)).unwrap(),
            before
        );
    }

    #[test]
    fn captured_inventory_storage_is_precharged_and_updates_without_growth() {
        let required = 32 * size_of::<Event>()
            + OWNER_BYTES
            + 4096
            + CAPTURED_CAPACITY * size_of::<CapturedReceipt>()
            + CAPTURED_REALM_CAPACITY * size_of::<CapturedRealm>();
        let short = MemoryBudget::new(required - 1);
        assert!(Recording::test_new(&short).is_err());
        assert_eq!(short.used(), 0);
        let budget = MemoryBudget::new(required);
        let mut r = Recording::test_new(&budget).unwrap();
        assert_eq!(budget.used(), required);
        let storage = r.captured_realms.as_ptr();
        let capacity = r.captured_realms.capacity();
        let entry = CapturedRealmCandidate {
            pin_path: Path::new("/actual/pin"),
            program_id: 1,
            realm_index: 2,
            closed_epoch: 3,
            state: CapturedRealmState::Installed,
        };
        for _ in 0..3 {
            r.captured_inventory(
                4,
                CapturedInventoryStatus::Committed,
                (0..CAPTURED_REALM_CAPACITY).map(|realm_index| CapturedRealmCandidate {
                    realm_index: realm_index as u32,
                    ..entry
                }),
            )
            .unwrap();
            assert_eq!(r.captured_inventory.unwrap().len, CAPTURED_REALM_CAPACITY);
            assert_eq!(r.captured_realms.as_ptr(), storage);
            assert_eq!(r.captured_realms.capacity(), capacity);
            assert_eq!(budget.used(), required);
        }
        assert_eq!(r.captured_len, 0);
        assert!(!r.accounting_error && !r.recording_error);
        drop(r);
        assert_eq!(budget.used(), 0);
    }
    fn identity(id: u64) -> HookIdentity {
        HookIdentity {
            hook_id: id,
            target_serial: id.div_ceil(2),
            kind: ((id - 1) & 1) as u32,
            scope: 1,
            namespace_cookie: 2,
            ifindex: 3,
            attachment_generation: 1,
            counter_map_id: 4 + ((id - 1) / 2) as u32,
            program_id: 0,
        }
    }
    fn initialize(r: &mut Recording) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = r
            .initialize_export(directory.path(), Snapshot::default())
            .unwrap();
        (directory, path)
    }
    fn finish(r: &mut Recording) -> Snapshot {
        let op = r.operation();
        let time = r.time().unwrap();
        r.append(Event {
            kind: NATIVE_EVENT_CLOSE_DRAINED,
            operation_id: op,
            related_seq: 1,
            boottime_after_ns: time,
            flags: NATIVE_EVENT_FLAG_TIMESTAMP_VALID,
            reason: NativeReason::Shutdown as u32,
            outcome: NATIVE_OUTCOME_COMMITTED,
            ..Event::default()
        });
        let ids: Vec<_> = r.hooks[..r.hook_count]
            .iter()
            .map(|h| h.identity.hook_id)
            .collect();
        for hook_id in ids {
            r.append(Event {
                kind: NATIVE_EVENT_CLOSED_COUNTS_FINAL,
                hook_id,
                related_seq: 1,
                counter_value: u64::MAX,
                flags: NATIVE_EVENT_FLAG_COUNTER_VALID,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            });
        }
        r.append(Event {
            kind: NATIVE_EVENT_TERMINAL_STATE,
            operation_id: op,
            related_seq: 1,
            reason: NativeReason::Shutdown as u32,
            outcome: NATIVE_OUTCOME_COMMITTED,
            ..Event::default()
        });
        r.append(Event {
            kind: NATIVE_EVENT_COLLECTION_END,
            boottime_after_ns: time,
            flags: NATIVE_EVENT_FLAG_TIMESTAMP_VALID,
            reason: NativeReason::Shutdown as u32,
            outcome: NATIVE_OUTCOME_COMMITTED,
            ..Event::default()
        });
        r.completed = true;
        r.hooks_joined = true;
        Snapshot {
            terminal: true,
            hooks_joined: true,
            all_counters_sealed: true,
            ..Snapshot::default()
        }
    }
    fn decimal(value: &Value) -> anyhow::Result<u64> {
        let text = value.as_str().context("missing decimal string")?;
        ensure!(
            !text.is_empty()
                && (text == "0" || !text.starts_with('0'))
                && text.bytes().all(|b| b.is_ascii_digit()),
            "noncanonical decimal string"
        );
        Ok(text.parse()?)
    }
    fn number(value: &Value) -> anyhow::Result<u32> {
        value
            .as_u64()
            .context("missing u32")?
            .try_into()
            .context("u32 overflow")
    }
    fn boolean(value: &Value) -> anyhow::Result<bool> {
        value.as_bool().context("missing boolean")
    }
    fn parse_event(value: &Value) -> anyhow::Result<Event> {
        ensure!(value["version"] == 1, "unsupported event version");
        let event = Event {
            seq: decimal(&value["seq"])?,
            operation_id: decimal(&value["operation_id"])?,
            writer_id: decimal(&value["writer_id"])?,
            epoch_before: decimal(&value["epoch_before"])?,
            epoch_after: decimal(&value["epoch_after"])?,
            boottime_before_ns: decimal(&value["boottime_before_ns"])?,
            boottime_after_ns: decimal(&value["boottime_after_ns"])?,
            related_seq: decimal(&value["related_seq"])?,
            counter_epoch: decimal(&value["counter_epoch"])?,
            counter_value: decimal(&value["counter_value"])?,
            hook_id: decimal(&value["hook_id"])?,
            outcome: number(&value["outcome"])?,
            kind: number(&value["kind"])?,
            reason: number(&value["reason"])?,
            flags: number(&value["flags"])?,
            reserved: serde_json::from_value(value["reserved"].clone())?,
        };
        validate_event(&event)?;
        if event.kind == NATIVE_EVENT_PROGRAM_REPLACED {
            ensure!(
                decimal(&value["old_program_id"])? == event.counter_value
                    && decimal(&value["new_program_id"])? == event.counter_epoch,
                "contradictory program projection"
            );
        } else {
            ensure!(
                value["old_program_id"].is_null() && value["new_program_id"].is_null(),
                "inapplicable program projection"
            );
        }
        Ok(event)
    }
    // A host consumer fixture may allocate a parsed document; the product exporter never does.
    fn parse_complete(bytes: &[u8], result: &NativeExportResult) -> anyhow::Result<()> {
        ensure!(
            result.status == NativeExportPublicationResult::PublishedDurable
                && result.error.is_none()
                && result.final_export
                && result.complete,
            "missing durable complete shutdown result"
        );
        ensure!(
            result.bytes == bytes.len() as u64
                && result.sha256.as_deref()
                    == Some(crate::configuration::encode_digest(&Sha256::digest(bytes)).as_str()),
            "artifact digest binding differs"
        );
        let value: Value = serde_json::from_slice(bytes)?;
        ensure!(
            value["schema"] == SCHEMA
                && value["clock_id"] == "CLOCK_BOOTTIME"
                && value["unit"] == "ns",
            "unsupported artifact schema or clock"
        );
        ensure!(
            value["boot_id"].as_str() == Some(std::str::from_utf8(&result.boot_id)?)
                && number(&value["pid"])? == result.pid
                && decimal(&value["starttime_ticks"])? == result.starttime_ticks
                && decimal(&value["publication_serial"])? == result.publication_serial
                && number(&value["root_map_id"])? == result.root_map_id
                && result.root_map_id != 0,
            "artifact identity binding differs"
        );
        let filename = format!(
            "{}-{}-{}.json",
            result.pid, result.starttime_ticks, result.publication_serial
        );
        ensure!(
            result
                .path
                .as_ref()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n == filename.as_str()),
            "artifact discovery path binding differs"
        );
        ensure!(
            boolean(&value["final"])?
                && boolean(&value["complete"])?
                && value["incomplete_reasons"] == serde_json::json!([]),
            "incomplete artifact header"
        );
        let snapshot = Snapshot {
            epoch: decimal(&value["final_epoch"])?,
            flags: number(&value["final_flags"])?,
            ready: boolean(&value["ready"])?,
            capture_ready: boolean(&value["capture_ready"])?,
            failed: boolean(&value["failed"])?,
            terminal: boolean(&value["terminal"])?,
            hooks_joined: boolean(&value["hooks_joined"])?,
            all_counters_sealed: boolean(&value["all_counters_sealed"])?,
        };
        let mut replay = Recording::allocate(
            &MemoryBudget::new(2 << 20),
            result.root_map_id,
            CAPACITY,
            4096,
            true,
        )?;
        replay.collection_start = Some(decimal(&value["collection_start_ns"])?);
        for h in value["hooks"]
            .as_array()
            .context("missing hook identities")?
        {
            ensure!(
                decimal(&h["publication_serial"])? == result.publication_serial,
                "hook publication binding differs"
            );
            replay.register_hook(HookIdentity {
                hook_id: decimal(&h["hook_id"])?,
                target_serial: decimal(&h["target_serial"])?,
                kind: number(&h["kind"])?,
                scope: decimal(&h["scope"])?,
                namespace_cookie: decimal(&h["namespace_cookie"])?,
                ifindex: number(&h["ifindex"])?,
                attachment_generation: decimal(&h["attachment_generation"])?,
                counter_map_id: number(&h["counter_map_id"])?,
                program_id: number(&h["initial_program_id"])?,
            })?;
            let hook = &mut replay.hooks[replay.hook_count - 1];
            hook.registered_seq = decimal(&h["registered_seq"])?;
            hook.current_program = number(&h["current_program_id"])?;
            hook.current_generation = decimal(&h["current_attachment_generation"])?;
        }
        replay.len = 0;
        replay.head = 0;
        replay.last_seq = 0;
        replay.total_appended = 0;
        for e in value["events"].as_array().context("missing events")? {
            let event = parse_event(e)?;
            ensure!(
                event.seq == replay.last_seq + 1,
                "duplicate, missing or reordered event"
            );
            replay.last_operation = replay.last_operation.max(event.operation_id);
            replay.last_writer = replay.last_writer.max(event.writer_id);
            ensure!(
                replay.append(event) == event.seq,
                "unsupported event identity"
            );
        }
        ensure!(
            decimal(&value["first_retained_seq"])? == 1
                && decimal(&value["last_seq"])? == replay.last_seq
                && result.last_seq == replay.last_seq
                && decimal(&value["total_appended"])? == replay.last_seq
                && decimal(&value["overwritten_events"])? == 0
                && replay.len as u64 == replay.last_seq,
            "inconsistent retained range"
        );
        ensure!(
            decimal(&value["initial_epoch"])? == 0 && number(&value["initial_flags"])? == 0,
            "contradictory initial state"
        );
        let first = replay.events().next().context("missing initial event")?;
        let end = replay.events().last().context("missing collection end")?;
        ensure!(
            decimal(&value["collection_start_ns"])? == first.boottime_after_ns
                && decimal(&value["collection_end_ns"])? == end.boottime_after_ns
                && end.boottime_after_ns >= first.boottime_after_ns,
            "contradictory collection interval"
        );
        for key in [
            "recording_error",
            "clock_error",
            "accounting_error",
            "counter_overflow",
            "export_error",
        ] {
            ensure!(!boolean(&value[key])?, "artifact reports {key}");
        }
        replay.completed = true;
        replay.hooks_joined = snapshot.hooks_joined;
        // Replaying a document cannot recreate the producer-held initial checkpoint tuple.
        ensure!(
            replay.incomplete_reasons(true, snapshot) == 1 << 1,
            "artifact history or finalization incomplete"
        );
        Ok(())
    }
    fn rebind_fixture(result: &mut NativeExportResult, value: &Value) -> Vec<u8> {
        let bytes = serde_json::to_vec(value).unwrap();
        result.sha256 = Some(crate::configuration::encode_digest(&Sha256::digest(&bytes)));
        result.bytes = bytes.len() as u64;
        bytes
    }

    #[test]
    fn initial_manifest_precedes_hooks_and_final_stream_binds_full_width_integers() {
        let mut r = recording();
        let (_dir, path) = initialize(&mut r);
        let initial_bytes = std::fs::read(&path).unwrap();
        let checkpoint = r.initial_checkpoint().unwrap();
        assert_eq!(
            checkpoint.0,
            _dir.path()
                .join("state/native-publication-initial")
                .join(path.file_name().unwrap())
        );
        assert_eq!(
            checkpoint.1,
            <[u8; 32]>::from(Sha256::digest(&initial_bytes))
        );
        assert_eq!(checkpoint.2, initial_bytes.len() as u64);
        assert_eq!(std::fs::read(&checkpoint.0).unwrap(), initial_bytes);
        let mutable_metadata = std::fs::metadata(&path).unwrap();
        let checkpoint_metadata = std::fs::metadata(&checkpoint.0).unwrap();
        assert_ne!(
            (mutable_metadata.dev(), mutable_metadata.ino()),
            (checkpoint_metadata.dev(), checkpoint_metadata.ino())
        );
        assert_eq!(mutable_metadata.nlink(), 1);
        assert_eq!(checkpoint_metadata.nlink(), 1);
        assert_eq!(checkpoint_metadata.mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(checkpoint.0.parent().unwrap())
                .unwrap()
                .mode()
                & 0o777,
            0o700
        );
        let initial: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(initial["final"], false);
        assert_eq!(initial["complete"], false);
        assert_eq!(initial["events"].as_array().unwrap().len(), 1);
        assert!(initial["hooks"].as_array().unwrap().is_empty());
        r.register_hook(identity(1)).unwrap();
        let first = r.export(false, Snapshot::default());
        assert_eq!(
            first.status,
            NativeExportPublicationResult::PublishedDurable
        );
        assert!(first.error.is_none());
        r.register_hook(identity(2)).unwrap();
        let second = r.export(false, Snapshot::default());
        assert_eq!(
            second.status,
            NativeExportPublicationResult::PublishedDurable
        );
        assert!(second.error.is_none());
        assert!(second.last_seq > first.last_seq);
        let snapshot = finish(&mut r);
        let result = r.export(true, snapshot);
        let bytes = std::fs::read(&path).unwrap();
        parse_complete(&bytes, &result).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            value["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["counter_value"] == "18446744073709551615")
        );
        assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(r.initial_checkpoint(), Some(checkpoint.clone()));
        assert_ne!(bytes, initial_bytes);
        drop(r);
        assert_eq!(std::fs::read(&checkpoint.0).unwrap(), initial_bytes);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(std::fs::read(&checkpoint.0).unwrap())),
            checkpoint.1
        );
    }
    #[test]
    fn initial_checkpoint_failures_never_promote_or_adopt_installed_prefixes() {
        for fault in [
            ExportFault::Write,
            ExportFault::ShortWrite,
            ExportFault::FileSync,
            ExportFault::CheckpointParentSync,
            ExportFault::CheckpointWrite,
            ExportFault::CheckpointSourceChanged,
            ExportFault::CheckpointFileSync,
            ExportFault::CheckpointDirectorySync,
            ExportFault::Rename,
            ExportFault::DirectorySync,
        ] {
            for existing_directory in [false, true] {
                let mut r = recording();
                let directory = tempfile::tempdir().unwrap();
                let path = r
                    .prepare_destination(directory.path(), Snapshot::default())
                    .unwrap();
                let checkpoint = r.destination.as_ref().unwrap().checkpoint_path().unwrap();
                if existing_directory {
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .create(checkpoint.parent().unwrap())
                        .unwrap();
                }
                r.fault = Some(fault);
                let result = r.export(false, Snapshot::default());
                assert!(result.error.is_some());
                assert!(!result.complete);
                assert_eq!(r.initial_checkpoint(), None);
                assert_ne!(
                    r.incomplete_reasons(true, Snapshot::default()) & (1 << 1),
                    0
                );
                let mutable_installed = fault == ExportFault::DirectorySync;
                let checkpoint_installed = mutable_installed
                    || fault == ExportFault::Rename
                    || fault == ExportFault::CheckpointDirectorySync;
                assert_eq!(path.exists(), mutable_installed);
                assert_eq!(checkpoint.exists(), checkpoint_installed);
                assert_eq!(
                    result.status,
                    if mutable_installed {
                        NativeExportPublicationResult::PublishedDurabilityUnknown
                    } else {
                        NativeExportPublicationResult::NotPublished
                    }
                );
                if mutable_installed {
                    let bytes = std::fs::read(&path).unwrap();
                    assert_eq!(result.bytes, bytes.len() as u64);
                    assert_eq!(
                        result.sha256,
                        Some(crate::configuration::encode_digest(&Sha256::digest(&bytes)))
                    );
                } else {
                    assert!(result.sha256.is_none());
                    assert_eq!(result.bytes, 0);
                }
                let prefix = std::fs::read(&checkpoint).ok();
                r.fault = None;
                let retry = r.export(false, Snapshot::default());
                assert!(retry.error.is_some());
                assert_eq!(retry.status, NativeExportPublicationResult::NotPublished);
                assert_eq!(r.initial_checkpoint(), None);
                assert_eq!(std::fs::read(&checkpoint).ok(), prefix);
                assert_eq!(path.exists(), mutable_installed);
                assert!(
                    r.initialize_export(directory.path(), Snapshot::default())
                        .is_err()
                );
                assert!(r.register_hook(identity(1)).is_err());
                assert_eq!(r.initial_checkpoint(), None);
                for parent in [path.parent().unwrap(), checkpoint.parent().unwrap()] {
                    if parent.exists() {
                        assert!(std::fs::read_dir(parent).unwrap().all(|entry| {
                            !entry.unwrap().file_name().as_bytes().ends_with(b".tmp")
                        }));
                    }
                }
            }
        }
    }
    #[test]
    fn checkpoint_copies_the_completed_inode_without_reserializing() {
        let mut r = recording();
        let directory = tempfile::tempdir().unwrap();
        r.prepare_destination(directory.path(), Snapshot::default())
            .unwrap();
        let mut buffer = r.buffer.take().unwrap();
        let destination = r.destination.as_ref().unwrap();
        let mut original = Temporary::new(&destination.directory).unwrap();
        let bytes = vec![0xa5; BUFFER_BYTES * 2 + 17];
        original.file.write_all(&bytes).unwrap();
        original.file.sync_all().unwrap();
        let hash = Sha256::digest(&bytes).into();
        destination
            .checkpoint(&original, hash, bytes.len() as u64, &mut buffer, None)
            .unwrap();
        let checkpoint = destination.checkpoint_path().unwrap();
        assert_eq!(std::fs::read(&checkpoint).unwrap(), bytes);
        assert_eq!(original.file.metadata().unwrap().nlink(), 1);
        assert_eq!(std::fs::metadata(&checkpoint).unwrap().nlink(), 1);
        assert_ne!(
            original.file.metadata().unwrap().ino(),
            std::fs::metadata(&checkpoint).unwrap().ino()
        );
        drop(original);
        drop(r);
        assert_eq!(std::fs::read(checkpoint).unwrap(), bytes);
    }
    #[test]
    fn checkpoint_rejects_source_substitution_digest_length_mode_links_and_symlink() {
        for fault in 0..6 {
            let mut r = recording();
            let directory = tempfile::tempdir().unwrap();
            r.prepare_destination(directory.path(), Snapshot::default())
                .unwrap();
            let mut buffer = r.buffer.take().unwrap();
            let destination = r.destination.as_ref().unwrap();
            let mut original = Temporary::new(&destination.directory).unwrap();
            let bytes = b"actual completed source bytes";
            original.file.write_all(bytes).unwrap();
            original.file.sync_all().unwrap();
            let mut hash: [u8; 32] = Sha256::digest(bytes).into();
            let mut length = bytes.len() as u64;
            let source = destination.path.parent().unwrap().join(&original.name);
            let held = source.with_file_name("held-original");
            match fault {
                0 => hash[0] ^= 1,
                1 => length -= 1,
                2 => {
                    std::fs::rename(&source, &held).unwrap();
                    let mut replacement = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&source)
                        .unwrap();
                    replacement.write_all(bytes).unwrap();
                    assert_eq!(original.file.metadata().unwrap().nlink(), 1);
                }
                3 => original
                    .file
                    .set_permissions(std::fs::Permissions::from_mode(0o644))
                    .unwrap(),
                4 => std::fs::hard_link(&source, &held).unwrap(),
                _ => {
                    std::fs::rename(&source, &held).unwrap();
                    symlink(&held, &source).unwrap();
                }
            }
            assert!(
                destination
                    .checkpoint(&original, hash, length, &mut buffer, None)
                    .is_err()
            );
            let checkpoint = destination.checkpoint_path().unwrap();
            assert!(!checkpoint.exists());
            assert_eq!(
                std::fs::read_dir(checkpoint.parent().unwrap())
                    .unwrap()
                    .count(),
                0
            );
            assert_eq!(r.initial_checkpoint(), None);
        }
    }
    #[test]
    fn checkpoint_refuses_unsafe_directory_and_existing_file_without_adoption() {
        for fault in 0..5 {
            let mut r = recording();
            let directory = tempfile::tempdir().unwrap();
            let path = r
                .prepare_destination(directory.path(), Snapshot::default())
                .unwrap();
            let checkpoint = r.destination.as_ref().unwrap().checkpoint_path().unwrap();
            let parent = checkpoint.parent().unwrap();
            let foreign = directory.path().join("foreign");
            std::fs::write(&foreign, b"foreign checkpoint").unwrap();
            match fault {
                0 => std::fs::write(parent, b"not a directory").unwrap(),
                1 => symlink(path.parent().unwrap(), parent).unwrap(),
                _ => {
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .create(parent)
                        .unwrap();
                    if fault == 2 {
                        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))
                            .unwrap();
                    }
                    if fault == 3 {
                        let mut file = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(&checkpoint)
                            .unwrap();
                        file.write_all(b"preexisting checkpoint").unwrap();
                    } else if fault == 4 {
                        symlink(&foreign, &checkpoint).unwrap();
                    }
                }
            }
            let before = std::fs::symlink_metadata(&checkpoint)
                .ok()
                .map(|metadata| (metadata.dev(), metadata.ino()));
            let result = r.export(false, Snapshot::default());
            assert_eq!(result.status, NativeExportPublicationResult::NotPublished);
            assert!(result.error.is_some());
            assert_eq!(r.initial_checkpoint(), None);
            assert!(!path.exists());
            assert_eq!(
                std::fs::symlink_metadata(&checkpoint)
                    .ok()
                    .map(|metadata| (metadata.dev(), metadata.ino())),
                before
            );
            if fault == 3 {
                assert_eq!(
                    std::fs::read(&checkpoint).unwrap(),
                    b"preexisting checkpoint"
                );
            }
            assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign checkpoint");
        }
    }
    #[test]
    fn export_failures_distinguish_before_rename_from_directory_sync_after_rename() {
        for fault in [
            ExportFault::Write,
            ExportFault::ShortWrite,
            ExportFault::FileSync,
            ExportFault::Rename,
            ExportFault::DirectorySync,
        ] {
            let mut r = recording();
            let (_dir, path) = initialize(&mut r);
            let initial = std::fs::read(&path).unwrap();
            r.register_hook(identity(1)).unwrap();
            let snapshot = finish(&mut r);
            r.fault = Some(fault);
            let result = r.export(true, snapshot);
            let actual = std::fs::read(&path).unwrap();
            assert!(result.error.is_some());
            assert!(!result.complete);
            assert_eq!(result.path.as_ref(), Some(&path));
            assert_eq!(result.publication_serial, r.serial);
            assert_eq!(result.root_map_id, r.root_map_id);
            if fault == ExportFault::DirectorySync {
                assert_eq!(
                    result.status,
                    NativeExportPublicationResult::PublishedDurabilityUnknown
                );
                assert_ne!(actual, initial);
                assert_eq!(
                    result.sha256,
                    Some(crate::configuration::encode_digest(&Sha256::digest(
                        &actual
                    )))
                );
                assert_eq!(
                    serde_json::from_slice::<Value>(&actual).unwrap()["final"],
                    true
                );
            } else {
                assert_eq!(result.status, NativeExportPublicationResult::NotPublished);
                assert_eq!(actual, initial);
                assert!(result.sha256.is_none());
            }
            assert!(parse_complete(&actual, &result).is_err());
        }
    }
    #[test]
    fn reachable_failed_owner_exports_partial_with_provisional_counts() {
        let mut r = recording();
        let (_dir, path) = initialize(&mut r);
        r.register_hook(identity(1)).unwrap();
        let result = r.export(
            false,
            Snapshot {
                failed: true,
                ..Snapshot::default()
            },
        );
        assert_eq!(
            result.status,
            NativeExportPublicationResult::PublishedDurable
        );
        assert!(result.error.is_none());
        let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(value["final"], false);
        assert_eq!(value["complete"], false);
        assert_eq!(value["hooks_joined"], false);
        assert!(
            value["incomplete_reasons"]
                .as_array()
                .unwrap()
                .contains(&Value::from("UNSEALED_COUNTERS"))
        );
    }
    #[test]
    fn ring_suffix_and_identity_exhaustion_are_sticky() {
        let budget = MemoryBudget::new(1 << 20);
        let mut r = Recording::allocate(&budget, 1, 2, 4096, true).unwrap();
        for _ in 0..4 {
            r.append(Event {
                kind: NATIVE_EVENT_TERMINAL_STATE,
                reason: NativeReason::Shutdown as u32,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            });
        }
        assert_eq!(r.events().map(|e| e.seq).collect::<Vec<_>>(), [4, 5]);
        assert_eq!(r.overwritten_events, 3);
        assert_ne!(
            r.incomplete_reasons(true, Snapshot::default()) & (1 << 5),
            0
        );
        r.last_seq = u64::MAX;
        assert_eq!(
            r.append(Event {
                kind: NATIVE_EVENT_COLLECTION_END,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            }),
            0
        );
        assert!(r.recording_error);
        r.last_operation = u64::MAX;
        r.last_writer = u64::MAX;
        assert_eq!(r.operation(), 0);
        assert_eq!(r.writer(), 0);
    }
    #[test]
    fn bounded_identity_table_rejects_duplicates_unknown_writers_and_capacity() {
        let mut r = recording();
        for id in 1..=MAX_HOOKS as u64 {
            r.register_hook(identity(id)).unwrap();
        }
        assert!(r.register_hook(identity(MAX_HOOKS as u64 + 1)).is_err());
        assert!(r.recording_error);
        let mut r = recording();
        r.register_hook(identity(1)).unwrap();
        assert!(r.register_hook(identity(1)).is_err());
        let mut r = recording();
        assert_eq!(
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id: 1,
                operation_id: 1,
                reason: NativeReason::Policy as u32,
                ..Event::default()
            }),
            0
        );
        assert!(r.recording_error);
        let mut r = recording();
        assert_eq!(
            r.append(Event {
                kind: NATIVE_EVENT_CLOSED_COUNTS_FINAL,
                hook_id: 1,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            }),
            0
        );
    }
    #[test]
    fn recording_reservation_precedes_allocation_and_remains_until_drop() {
        assert!(size_of::<Recording>() <= OWNER_BYTES);
        let required = CAPACITY * size_of::<Event>()
            + OWNER_BYTES.max(size_of::<Recording>())
            + BUFFER_BYTES
            + CAPTURED_CAPACITY * size_of::<CapturedReceipt>()
            + CAPTURED_REALM_CAPACITY * size_of::<CapturedRealm>();
        assert_eq!(
            required,
            598016
                + CAPTURED_CAPACITY * size_of::<CapturedReceipt>()
                + CAPTURED_REALM_CAPACITY * size_of::<CapturedRealm>()
        );
        let short = MemoryBudget::new(required - 1);
        assert!(Recording::new(&short, 0).is_err());
        assert_eq!(short.used(), 0);
        let budget = MemoryBudget::new(required);
        let mut r = Recording::new(&budget, 0).unwrap();
        assert_eq!(budget.used(), required);
        r.set_root_map_id(1).unwrap();
        assert!(r.set_root_map_id(2).is_err());
        drop(r);
        assert_eq!(budget.used(), 0);
        let fixture = MemoryBudget::new(1 << 20);
        let r = Recording::test_new(&fixture).unwrap();
        assert!(fixture.used() > CAPTURED_CAPACITY * size_of::<CapturedReceipt>());
        drop(r);
        assert_eq!(fixture.used(), 0);
    }
    #[test]
    fn consumer_rejects_unknown_version_kind_flags_reserved_and_truncation() {
        let event = Event {
            kind: NATIVE_EVENT_INITIAL_STATE,
            ..Event::default()
        };
        let value = serde_json::to_value(EventProjection(&event)).unwrap();
        for (field, invalid) in [
            ("version", Value::from(2)),
            ("kind", Value::from(14)),
            ("flags", Value::from(512)),
            (
                "reserved",
                serde_json::json!([
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]),
            ),
        ] {
            let mut invalid_event = value.clone();
            invalid_event[field] = invalid;
            assert!(parse_event(&invalid_event).is_err());
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(serde_json::from_slice::<Value>(&bytes[..bytes.len() - 1]).is_err());
        let mut invalid = value;
        invalid["seq"] = Value::from(18446744073709551615u64);
        assert!(parse_event(&invalid).is_err());
    }
    #[test]
    fn actual_program_replacement_chain_rejects_pending_omitted_and_mismatched_events() {
        let mut r = recording();
        let (_dir, path) = initialize(&mut r);
        r.register_hook(identity(1)).unwrap();
        let op = r.operation();
        let writer = r.writer();
        r.append(Event {
            kind: NATIVE_EVENT_WRITER_BEGIN,
            operation_id: op,
            writer_id: writer,
            reason: NativeReason::Reload as u32,
            ..Event::default()
        });
        r.program_replacement(
            1,
            0,
            10,
            NATIVE_OUTCOME_PENDING,
            NativeReason::Reload,
            op,
            writer,
        )
        .unwrap();
        assert_eq!(r.hooks[0].current_program, 0);
        assert_ne!(
            r.incomplete_reasons(true, Snapshot::default()) & (1 << 13),
            0
        );
        r.program_replacement(
            1,
            0,
            10,
            NATIVE_OUTCOME_COMMITTED,
            NativeReason::Reload,
            op,
            writer,
        )
        .unwrap();
        r.append(Event {
            kind: NATIVE_EVENT_WRITER_OUTCOME,
            operation_id: op,
            writer_id: writer,
            reason: NativeReason::Reload as u32,
            outcome: NATIVE_OUTCOME_COMMITTED,
            ..Event::default()
        });
        assert_eq!(r.hooks[0].identity.program_id, 0);
        assert_eq!(r.hooks[0].current_program, 10);
        assert_eq!(r.hooks[0].current_generation, 2);
        let snapshot = finish(&mut r);
        let mut result = r.export(true, snapshot);
        let bytes = std::fs::read(path).unwrap();
        parse_complete(&bytes, &result).unwrap();
        let original: Value = serde_json::from_slice(&bytes).unwrap();
        let index = original["events"]
            .as_array()
            .unwrap()
            .iter()
            .position(|e| e["kind"] == 13 && e["outcome"] == 1)
            .unwrap();
        for fault in 0..3 {
            let mut value = original.clone();
            match fault {
                0 => {
                    value["events"][index]["outcome"] = Value::from(0);
                }
                1 => {
                    value["events"][index]["counter_value"] = Value::from("9");
                    value["events"][index]["old_program_id"] = Value::from("9");
                }
                _ => {
                    value["events"].as_array_mut().unwrap().remove(index);
                }
            }
            let bytes = rebind_fixture(&mut result, &value);
            assert!(parse_complete(&bytes, &result).is_err());
        }
    }
    #[test]
    fn live_writer_and_replacement_authority_survive_full_journal_eviction() {
        let mut r =
            Recording::allocate(&MemoryBudget::new(2 << 20), 1, CAPACITY, 4096, true).unwrap();
        r.register_hook(identity(1)).unwrap();
        let writer_id = r.writer();
        let root = r.operation();
        assert_ne!(
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id,
                operation_id: root,
                reason: NativeReason::Reload as u32,
                ..Event::default()
            }),
            0
        );
        assert_ne!(
            r.append(Event {
                kind: NATIVE_EVENT_CLOSE_STORED,
                writer_id,
                operation_id: root,
                epoch_after: 2,
                reason: NativeReason::Reload as u32,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            }),
            0
        );
        let participant = r.operation();
        assert_ne!(
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id,
                operation_id: participant,
                reason: NativeReason::Policy as u32,
                ..Event::default()
            }),
            0
        );
        for _ in 0..=CAPACITY {
            let writer_id = r.writer();
            let operation_id = r.operation();
            assert_ne!(
                r.append(Event {
                    kind: NATIVE_EVENT_WRITER_BEGIN,
                    writer_id,
                    operation_id,
                    reason: NativeReason::Flags as u32,
                    ..Event::default()
                }),
                0
            );
            assert_ne!(
                r.append(Event {
                    kind: NATIVE_EVENT_WRITER_OUTCOME,
                    writer_id,
                    operation_id,
                    reason: NativeReason::Flags as u32,
                    outcome: NATIVE_OUTCOME_COMMITTED,
                    ..Event::default()
                }),
                0
            );
            assert_ne!(
                r.append(Event {
                    kind: NATIVE_EVENT_CLOSE_DRAINED,
                    reason: NativeReason::Flags as u32,
                    outcome: NATIVE_OUTCOME_COMMITTED,
                    ..Event::default()
                }),
                0
            );
        }
        assert!(r.is_live_writer(writer_id, root));
        assert!(
            !r.events().any(
                |event| event.kind == NATIVE_EVENT_WRITER_BEGIN && event.writer_id == writer_id
            )
        );
        assert_eq!(r.actual_epoch, 2);
        r.register_hook(identity(2)).unwrap();
        r.program_replacement(
            1,
            0,
            10,
            NATIVE_OUTCOME_PENDING,
            NativeReason::Policy,
            participant,
            writer_id,
        )
        .unwrap();
        r.program_replacement(
            1,
            0,
            10,
            NATIVE_OUTCOME_COMMITTED,
            NativeReason::Policy,
            participant,
            writer_id,
        )
        .unwrap();
        assert_ne!(
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_OUTCOME,
                writer_id,
                operation_id: participant,
                reason: NativeReason::Policy as u32,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            }),
            0
        );
        assert!(r.is_live_writer(writer_id, root));
        assert_ne!(
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_OUTCOME,
                writer_id,
                operation_id: root,
                reason: NativeReason::Reload as u32,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            }),
            0
        );
        assert!(!r.is_live_writer(writer_id, root));
        assert!(!r.recording_error);
        assert!(r.overwritten_events > 0);
        assert!(!r.history_complete(Snapshot::default()));
    }
    #[test]
    fn evicted_open_store_still_refuses_hook_and_replacement_admission() {
        for replacement in [false, true] {
            let mut r = recording();
            r.register_hook(identity(1)).unwrap();
            let writer_id = r.writer();
            let operation_id = r.operation();
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id,
                operation_id,
                reason: NativeReason::Reload as u32,
                ..Event::default()
            });
            r.append(Event {
                kind: NATIVE_EVENT_REOPEN_STORED,
                epoch_after: 1,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            });
            for _ in 0..64 {
                r.append(Event {
                    kind: NATIVE_EVENT_CLOSE_DRAINED,
                    outcome: NATIVE_OUTCOME_COMMITTED,
                    ..Event::default()
                });
            }
            assert!(!r.recording_error);
            if replacement {
                assert!(
                    r.program_replacement(
                        1,
                        0,
                        10,
                        NATIVE_OUTCOME_PENDING,
                        NativeReason::Reload,
                        operation_id,
                        writer_id
                    )
                    .is_err()
                );
            } else {
                assert!(r.register_hook(identity(2)).is_err());
            }
            assert!(r.recording_error);
        }
    }
    #[test]
    fn live_operation_storage_is_reserved_before_admission_and_retained_until_drop() {
        let base = 32 * size_of::<Event>()
            + OWNER_BYTES
            + 4096
            + CAPTURED_CAPACITY * size_of::<CapturedReceipt>()
            + CAPTURED_REALM_CAPACITY * size_of::<CapturedRealm>();
        let budget = MemoryBudget::new(base);
        let mut r = Recording::test_new(&budget).unwrap();
        let writer_id = r.writer();
        let operation_id = r.operation();
        assert_eq!(
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id,
                operation_id,
                reason: NativeReason::Reload as u32,
                ..Event::default()
            }),
            0
        );
        assert!(r.recording_error);
        assert!(!r.is_live_writer(writer_id, operation_id));
        assert_eq!(r.last_seq, 1);
        assert_eq!(budget.used(), base);
        drop(r);
        assert_eq!(budget.used(), 0);

        let budget = MemoryBudget::new(1 << 20);
        let mut r = Recording::test_new(&budget).unwrap();
        let writer_id = r.writer();
        let operation_id = r.operation();
        assert_ne!(
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id,
                operation_id,
                reason: NativeReason::Reload as u32,
                ..Event::default()
            }),
            0
        );
        let reserved = budget.used();
        assert!(reserved >= base + r.live_operations.capacity() * size_of::<LiveOperation>());
        assert_ne!(
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_OUTCOME,
                writer_id,
                operation_id,
                reason: NativeReason::Reload as u32,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            }),
            0
        );
        assert!(r.live_operations.is_empty());
        assert_eq!(budget.used(), reserved);
        let capacity = r.live_operations.capacity();
        for _ in 0..=capacity {
            let writer_id = r.writer();
            let operation_id = r.operation();
            assert_ne!(
                r.append(Event {
                    kind: NATIVE_EVENT_WRITER_BEGIN,
                    writer_id,
                    operation_id,
                    reason: NativeReason::Reload as u32,
                    ..Event::default()
                }),
                0
            );
        }
        assert!(r.live_operations.capacity() > capacity);
        assert!(budget.used() > reserved);
        drop(r);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn operations_reject_mismatched_writer_reason_and_reused_root_identity() {
        for fault in 0..4 {
            let mut r = recording();
            r.register_hook(identity(1)).unwrap();
            let writer_id = r.writer();
            let root = r.operation();
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id,
                operation_id: root,
                reason: NativeReason::Reload as u32,
                ..Event::default()
            });
            let other = r.writer();
            let other_root = r.operation();
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id: other,
                operation_id: other_root,
                reason: NativeReason::Reload as u32,
                ..Event::default()
            });
            let participant = r.operation();
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id,
                operation_id: participant,
                reason: NativeReason::Policy as u32,
                ..Event::default()
            });
            let invalid = match fault {
                0 => Event {
                    kind: NATIVE_EVENT_WRITER_OUTCOME,
                    writer_id: other,
                    operation_id: participant,
                    reason: NativeReason::Policy as u32,
                    outcome: NATIVE_OUTCOME_COMMITTED,
                    ..Event::default()
                },
                1 => Event {
                    kind: NATIVE_EVENT_PROGRAM_REPLACED,
                    writer_id: other,
                    operation_id: participant,
                    reason: NativeReason::Policy as u32,
                    hook_id: 1,
                    ..Event::default()
                },
                2 => Event {
                    kind: NATIVE_EVENT_WRITER_OUTCOME,
                    writer_id,
                    operation_id: participant,
                    reason: NativeReason::Reload as u32,
                    outcome: NATIVE_OUTCOME_COMMITTED,
                    ..Event::default()
                },
                _ => {
                    r.append(Event {
                        kind: NATIVE_EVENT_WRITER_OUTCOME,
                        writer_id,
                        operation_id: root,
                        reason: NativeReason::Reload as u32,
                        outcome: NATIVE_OUTCOME_COMMITTED,
                        ..Event::default()
                    });
                    assert!(!r.live_operations.iter().any(|op| op.writer_id == writer_id));
                    let operation_id = r.operation();
                    Event {
                        kind: NATIVE_EVENT_WRITER_BEGIN,
                        writer_id,
                        operation_id,
                        reason: NativeReason::Reload as u32,
                        ..Event::default()
                    }
                }
            };
            assert_eq!(r.append(invalid), 0);
            assert!(r.recording_error);
            assert!(r.is_live_writer(other, other_root));
        }
    }
    #[test]
    fn history_rejects_operation_writer_substitution_while_both_roots_are_live() {
        for replacement in [false, true] {
            let mut r = recording();
            r.register_hook(identity(1)).unwrap();
            let writer_id = r.writer();
            let root = r.operation();
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id,
                operation_id: root,
                reason: NativeReason::Reload as u32,
                ..Event::default()
            });
            let other = r.writer();
            let other_root = r.operation();
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id: other,
                operation_id: other_root,
                reason: NativeReason::Reload as u32,
                ..Event::default()
            });
            let participant = r.operation();
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id,
                operation_id: participant,
                reason: NativeReason::Policy as u32,
                ..Event::default()
            });
            r.program_replacement(
                1,
                0,
                10,
                NATIVE_OUTCOME_PENDING,
                NativeReason::Policy,
                participant,
                writer_id,
            )
            .unwrap();
            r.program_replacement(
                1,
                0,
                10,
                NATIVE_OUTCOME_COMMITTED,
                NativeReason::Policy,
                participant,
                writer_id,
            )
            .unwrap();
            for (writer_id, operation_id, reason) in [
                (writer_id, participant, NativeReason::Policy),
                (writer_id, root, NativeReason::Reload),
                (other, other_root, NativeReason::Reload),
            ] {
                r.append(Event {
                    kind: NATIVE_EVENT_WRITER_OUTCOME,
                    writer_id,
                    operation_id,
                    reason: reason as u32,
                    outcome: NATIVE_OUTCOME_COMMITTED,
                    ..Event::default()
                });
            }
            let snapshot = finish(&mut r);
            assert!(r.history_complete(snapshot));
            let kind = if replacement {
                NATIVE_EVENT_PROGRAM_REPLACED
            } else {
                NATIVE_EVENT_WRITER_OUTCOME
            };
            for event in &mut r.ring[..r.len] {
                if event.operation_id == participant && event.kind == kind {
                    event.writer_id = other;
                }
            }
            assert!(!r.history_complete(snapshot));
        }
    }
    #[test]
    fn writer_participants_and_replacements_require_their_live_root() {
        for kind in [
            NATIVE_EVENT_WRITER_BEGIN,
            NATIVE_EVENT_WRITER_OUTCOME,
            NATIVE_EVENT_PROGRAM_REPLACED,
        ] {
            let mut r = recording();
            r.register_hook(identity(1)).unwrap();
            let w1 = r.writer();
            let w2 = r.writer();
            let root1 = r.operation();
            let root2 = r.operation();
            for (writer_id, operation_id) in [(w1, root1), (w2, root2)] {
                assert_ne!(
                    r.append(Event {
                        kind: NATIVE_EVENT_WRITER_BEGIN,
                        writer_id,
                        operation_id,
                        reason: NativeReason::Reload as u32,
                        ..Event::default()
                    }),
                    0
                );
            }
            let participant1 = r.operation();
            let participant2 = r.operation();
            for (writer_id, operation_id) in [(w1, participant1), (w2, participant2)] {
                assert_ne!(
                    r.append(Event {
                        kind: NATIVE_EVENT_WRITER_BEGIN,
                        writer_id,
                        operation_id,
                        reason: NativeReason::Reload as u32,
                        ..Event::default()
                    }),
                    0
                );
            }
            assert_ne!(
                r.append(Event {
                    kind: NATIVE_EVENT_WRITER_OUTCOME,
                    writer_id: w1,
                    operation_id: root1,
                    reason: NativeReason::Reload as u32,
                    outcome: NATIVE_OUTCOME_COMMITTED,
                    ..Event::default()
                }),
                0
            );
            let operation1 = if kind == NATIVE_EVENT_WRITER_BEGIN {
                r.operation()
            } else {
                participant1
            };
            let operation2 = if kind == NATIVE_EVENT_WRITER_BEGIN {
                r.operation()
            } else {
                participant2
            };
            let event = Event {
                kind,
                operation_id: operation1,
                writer_id: w1,
                reason: NativeReason::Reload as u32,
                outcome: if kind == NATIVE_EVENT_WRITER_OUTCOME {
                    NATIVE_OUTCOME_COMMITTED
                } else {
                    NATIVE_OUTCOME_PENDING
                },
                hook_id: if kind == NATIVE_EVENT_PROGRAM_REPLACED {
                    1
                } else {
                    0
                },
                ..Event::default()
            };
            assert_eq!(r.append(event), 0);
            assert!(r.recording_error);
            assert_ne!(
                r.append(Event {
                    operation_id: operation2,
                    writer_id: w2,
                    ..event
                }),
                0
            );
        }
    }
    #[test]
    fn history_rejects_settled_root_participants_and_replacements() {
        for replacement in [false, true] {
            let mut r = recording();
            r.register_hook(identity(1)).unwrap();
            let w1 = r.writer();
            let w2 = r.writer();
            let root1 = r.operation();
            let root2 = r.operation();
            for (writer_id, operation_id) in [(w1, root1), (w2, root2)] {
                r.append(Event {
                    kind: NATIVE_EVENT_WRITER_BEGIN,
                    writer_id,
                    operation_id,
                    reason: NativeReason::Reload as u32,
                    ..Event::default()
                });
            }
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_OUTCOME,
                writer_id: w1,
                operation_id: root1,
                reason: NativeReason::Reload as u32,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            });
            let participant = r.operation();
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id: w2,
                operation_id: participant,
                reason: NativeReason::Reload as u32,
                ..Event::default()
            });
            r.program_replacement(
                1,
                0,
                10,
                NATIVE_OUTCOME_PENDING,
                NativeReason::Reload,
                participant,
                w2,
            )
            .unwrap();
            r.program_replacement(
                1,
                0,
                10,
                NATIVE_OUTCOME_COMMITTED,
                NativeReason::Reload,
                participant,
                w2,
            )
            .unwrap();
            for operation_id in [participant, root2] {
                r.append(Event {
                    kind: NATIVE_EVENT_WRITER_OUTCOME,
                    writer_id: w2,
                    operation_id,
                    reason: NativeReason::Reload as u32,
                    outcome: NATIVE_OUTCOME_COMMITTED,
                    ..Event::default()
                });
            }
            let snapshot = finish(&mut r);
            assert!(r.history_complete(snapshot));
            for event in &mut r.ring[..r.len] {
                if event.operation_id == participant
                    && (!replacement || event.kind == NATIVE_EVENT_PROGRAM_REPLACED)
                {
                    event.writer_id = w1;
                    if replacement {
                        event.operation_id = root1;
                    }
                }
            }
            assert!(!r.history_complete(snapshot));
        }
    }
    #[test]
    fn history_rejects_participant_outcome_after_root_settlement() {
        let mut r = recording();
        r.register_hook(identity(1)).unwrap();
        let writer_id = r.writer();
        let root = r.operation();
        let participant = r.operation();
        for operation_id in [root, participant] {
            r.append(Event {
                kind: NATIVE_EVENT_WRITER_BEGIN,
                writer_id,
                operation_id,
                reason: NativeReason::Reload as u32,
                ..Event::default()
            });
        }
        let participant_seq = r.append(Event {
            kind: NATIVE_EVENT_WRITER_OUTCOME,
            writer_id,
            operation_id: participant,
            reason: NativeReason::Reload as u32,
            outcome: NATIVE_OUTCOME_COMMITTED,
            ..Event::default()
        });
        let root_seq = r.append(Event {
            kind: NATIVE_EVENT_WRITER_OUTCOME,
            writer_id,
            operation_id: root,
            reason: NativeReason::Reload as u32,
            outcome: NATIVE_OUTCOME_COMMITTED,
            ..Event::default()
        });
        let snapshot = finish(&mut r);
        assert!(r.history_complete(snapshot));
        r.ring[(participant_seq - 1) as usize].operation_id = root;
        r.ring[(root_seq - 1) as usize].operation_id = participant;
        assert!(!r.history_complete(snapshot));
    }
    #[test]
    fn consumer_requires_matching_durable_result_and_every_finalization_marker() {
        let mut r = recording();
        let (_dir, path) = initialize(&mut r);
        r.register_hook(identity(1)).unwrap();
        let snapshot = finish(&mut r);
        let mut result = r.export(true, snapshot);
        let bytes = std::fs::read(&path).unwrap();
        parse_complete(&bytes, &result).unwrap();
        result.status = NativeExportPublicationResult::PublishedDurabilityUnknown;
        assert!(parse_complete(&bytes, &result).is_err());
        result.status = NativeExportPublicationResult::PublishedDurable;
        result.publication_serial += 1;
        assert!(parse_complete(&bytes, &result).is_err());
        result.publication_serial -= 1;
        let original: Value = serde_json::from_slice(&bytes).unwrap();
        for fault in 0..6 {
            let mut value = original.clone();
            match fault {
                0 => value["events"][1]["seq"] = Value::from("1"),
                1 => value["hooks_joined"] = Value::from(false),
                2 => value["all_counters_sealed"] = Value::from(false),
                3 => value["last_seq"] = Value::from("100"),
                4 => {
                    let i = value["events"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .position(|e| e["kind"] == 10)
                        .unwrap();
                    value["events"][i]["counter_epoch"] = Value::from("2");
                }
                _ => {
                    value["events"].as_array_mut().unwrap().pop();
                }
            }
            let bytes = rebind_fixture(&mut result, &value);
            assert!(parse_complete(&bytes, &result).is_err());
        }
    }
    #[test]
    fn consumer_rejects_pending_settled_milestones() {
        let mut r = recording();
        let (_dir, path) = initialize(&mut r);
        r.register_hook(identity(1)).unwrap();
        let operation_id = r.operation();
        let writer_id = r.writer();
        r.append(Event {
            kind: NATIVE_EVENT_WRITER_BEGIN,
            operation_id,
            writer_id,
            reason: NativeReason::Ready as u32,
            ..Event::default()
        });
        r.append(Event {
            kind: NATIVE_EVENT_WRITER_OUTCOME,
            operation_id,
            writer_id,
            reason: NativeReason::Ready as u32,
            outcome: NATIVE_OUTCOME_COMMITTED,
            ..Event::default()
        });
        let snapshot = finish(&mut r);
        let mut result = r.export(true, snapshot);
        let bytes = std::fs::read(path).unwrap();
        parse_complete(&bytes, &result).unwrap();
        let original: Value = serde_json::from_slice(&bytes).unwrap();
        for kind in [
            NATIVE_EVENT_WRITER_OUTCOME,
            NATIVE_EVENT_CLOSE_DRAINED,
            NATIVE_EVENT_CLOSED_COUNTS_FINAL,
            NATIVE_EVENT_TERMINAL_STATE,
            NATIVE_EVENT_COLLECTION_END,
        ] {
            let mut value = original.clone();
            let index = value["events"]
                .as_array()
                .unwrap()
                .iter()
                .position(|e| e["kind"] == kind)
                .unwrap();
            value["events"][index]["outcome"] = Value::from(NATIVE_OUTCOME_PENDING);
            assert!(parse_event(&value["events"][index]).is_err());
            let bytes = rebind_fixture(&mut result, &value);
            assert!(parse_complete(&bytes, &result).is_err());
        }
        for kind in [NATIVE_EVENT_CLOSE_STORED, NATIVE_EVENT_REOPEN_STORED] {
            let mut value = serde_json::to_value(EventProjection(&Event {
                kind,
                outcome: NATIVE_OUTCOME_COMMITTED,
                ..Event::default()
            }))
            .unwrap();
            parse_event(&value).unwrap();
            value["outcome"] = Value::from(NATIVE_OUTCOME_PENDING);
            assert!(parse_event(&value).is_err());
        }
    }
    #[test]
    fn clock_and_counter_faults_remain_sticky_after_valid_samples() {
        let mut r = recording();
        r.fail_clock_for_test(true);
        assert_eq!(r.time(), None);
        assert!(r.clock_error);
        r.fail_clock_for_test(false);
        assert!(r.time().is_some());
        assert!(r.clock_error);
        r.register_hook(identity(1)).unwrap();
        r.append(Event {
            kind: NATIVE_EVENT_CLOSED_COUNTS_FINAL,
            hook_id: 1,
            flags: NATIVE_EVENT_FLAG_COUNTER_VALID | NATIVE_EVENT_FLAG_COUNTER_OVERFLOW,
            outcome: NATIVE_OUTCOME_COMMITTED,
            ..Event::default()
        });
        assert!(r.counter_overflow);
        assert_ne!(
            r.incomplete_reasons(true, Snapshot::default()) & (1 << 7),
            0
        );
        assert_ne!(
            r.incomplete_reasons(true, Snapshot::default()) & (1 << 9),
            0
        );
    }
    #[test]
    fn manifest_advertises_bounded_tables_and_refuses_overlong_path_before_attachment() {
        let mut r = recording();
        let (_dir, path) = initialize(&mut r);
        let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(value["max_targets"], 16);
        assert_eq!(value["max_hooks"], 32);
        assert_eq!(value["data_dir_path_max_bytes"], 1024);
        let mut r = recording();
        let too_long = PathBuf::from(format!("/{}", "a".repeat(1024)));
        assert!(r.initialize_export(&too_long, Snapshot::default()).is_err());
        assert!(r.recording_error);
        assert!(r.destination.is_none());
        assert_eq!(r.hook_count, 0);
        assert_eq!(r.initial_checkpoint(), None);
        let directory = tempfile::tempdir().unwrap();
        assert!(
            r.initialize_export(directory.path(), Snapshot::default())
                .is_err()
        );
        assert!(r.register_hook(identity(1)).is_err());
        assert_eq!(r.initial_checkpoint(), None);
        let mut r = recording();
        r.register_hook(identity(1)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        assert!(
            r.initialize_export(dir.path(), Snapshot::default())
                .is_err()
        );
    }
    #[test]
    fn symlink_paths_and_external_artifact_replacement_are_refused() {
        let mut r = recording();
        let (dir, path) = initialize(&mut r);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"foreign").unwrap();
        let result = r.export(false, Snapshot::default());
        assert_eq!(result.status, NativeExportPublicationResult::NotPublished);
        assert!(result.error.is_some());
        assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
        let link = dir.path().join("linked");
        symlink(path.parent().unwrap(), &link).unwrap();
        assert!(open_directory(&link).is_err());
        let fresh = tempfile::tempdir().unwrap();
        symlink(dir.path().join("state"), fresh.path().join("state")).unwrap();
        assert!(
            recording()
                .initialize_export(fresh.path(), Snapshot::default())
                .is_err()
        );
    }
}
