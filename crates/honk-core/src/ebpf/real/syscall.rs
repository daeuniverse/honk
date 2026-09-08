//! Raw extensions for BPF map commands that Aya 0.14 does not expose.
//!
//! Ordinary map reads, writes, deletes, iteration, and per-CPU access use
//! Aya's typed map APIs in `real::mod`. This module owns the atomic and batch
//! commands plus locked access to the persistent UDP token allocator.

use super::*;

use aya::Pod;
use aya_obj::generated::bpf_cmd::*;
use aya_obj::generated::{BPF_ANY, BPF_F_LOCK, bpf_attr, bpf_map_info, bpf_map_type};
use std::ffi::c_long;
use std::mem::MaybeUninit;
use std::path::Path;

const ENOENT: c_long = libc::ENOENT as c_long;
pub const BPF_BATCH_CHUNK: usize = 128;

pub enum LookupAndDelete<V> {
    Unsupported,
    Missing,
    Value(V),
}

pub type BatchVisitor<'a, K, V> = dyn FnMut(&[(K, V)]) -> bool + 'a;

pub(super) unsafe fn bpf_syscall(cmd: c_long, attr: &mut bpf_attr) -> Result<(), c_long> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *mut bpf_attr,
            core::mem::size_of::<bpf_attr>(),
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO) as c_long)
    } else {
        Ok(())
    }
}

fn map_raw_fd(map: &aya::maps::Map) -> RawFd {
    use aya::maps::Map;
    let data: &aya::maps::MapData = match map {
        Map::Array(d)
        | Map::ArrayOfMaps(d)
        | Map::BloomFilter(d)
        | Map::CgroupArray(d)
        | Map::CgroupStorage(d)
        | Map::CgrpStorage(d)
        | Map::CpuMap(d)
        | Map::DevMap(d)
        | Map::DevMapHash(d)
        | Map::HashMap(d)
        | Map::HashOfMaps(d)
        | Map::InodeStorage(d)
        | Map::LpmTrie(d)
        | Map::LruHashMap(d)
        | Map::PerCpuArray(d)
        | Map::PerCpuCgroupStorage(d)
        | Map::PerCpuHashMap(d)
        | Map::PerCpuLruHashMap(d)
        | Map::PerfEventArray(d)
        | Map::ProgramArray(d)
        | Map::Queue(d)
        | Map::ReusePortSockArray(d)
        | Map::RingBuf(d)
        | Map::SockHash(d)
        | Map::SockMap(d)
        | Map::SkStorage(d)
        | Map::Stack(d)
        | Map::StackTraceMap(d)
        | Map::Unsupported(d)
        | Map::XskMap(d) => d,
    };
    data.fd().as_fd().as_raw_fd()
}

fn map_fd(bpf: &Ebpf, name: &str) -> anyhow::Result<RawFd> {
    bpf.map(name)
        .map(map_raw_fd)
        .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))
}

fn raw_map_info(fd: RawFd) -> anyhow::Result<bpf_map_info> {
    let mut info: bpf_map_info = unsafe { core::mem::zeroed() };
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.info.bpf_fd = fd as u32;
    attr.info.info_len = core::mem::size_of::<bpf_map_info>() as u32;
    attr.info.info = (&mut info as *mut bpf_map_info) as u64;
    unsafe { bpf_syscall(BPF_OBJ_GET_INFO_BY_FD as c_long, &mut attr) }
        .map_err(|error| anyhow::anyhow!("BPF_OBJ_GET_INFO_BY_FD errno={error}"))?;
    Ok(info)
}

fn locked_udp_decision_sequence(fd: RawFd) -> anyhow::Result<UdpDecisionSequence> {
    let key = 0u32;
    let mut value = UdpDecisionSequence::default();
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = (&key as *const u32) as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = (&mut value as *mut UdpDecisionSequence) as u64;
    attr.__bindgen_anon_2.flags = BPF_F_LOCK as u64;
    unsafe { bpf_syscall(BPF_MAP_LOOKUP_ELEM as c_long, &mut attr) }.map_err(|error| {
        anyhow::anyhow!(
            "locked UDP_DECISION_SEQUENCE lookup failed (spin-lock BTF incompatible), errno={error}"
        )
    })?;
    Ok(value)
}

fn update_locked_udp_decision_sequence(
    fd: RawFd,
    value: &UdpDecisionSequence,
) -> anyhow::Result<()> {
    let key = 0u32;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = (&key as *const u32) as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = (value as *const UdpDecisionSequence) as u64;
    attr.__bindgen_anon_2.flags = (BPF_ANY | BPF_F_LOCK) as u64;
    unsafe { bpf_syscall(BPF_MAP_UPDATE_ELEM as c_long, &mut attr) }.map_err(|error| {
        anyhow::anyhow!(
            "locked UDP_DECISION_SEQUENCE update failed (spin-lock BTF incompatible), errno={error}"
        )
    })?;
    Ok(())
}

fn validate_udp_decision_sequence_info(info: &bpf_map_info) -> anyhow::Result<()> {
    anyhow::ensure!(
        info.type_ == bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
        "UDP_DECISION_SEQUENCE has incompatible map type {}",
        info.type_
    );
    anyhow::ensure!(
        info.key_size == core::mem::size_of::<u32>() as u32,
        "UDP_DECISION_SEQUENCE has incompatible key size {}",
        info.key_size
    );
    anyhow::ensure!(
        info.value_size == core::mem::size_of::<UdpDecisionSequence>() as u32,
        "UDP_DECISION_SEQUENCE has incompatible value size {}",
        info.value_size
    );
    anyhow::ensure!(
        info.max_entries == 1,
        "UDP_DECISION_SEQUENCE has incompatible max_entries {}",
        info.max_entries
    );
    anyhow::ensure!(
        info.map_flags == 0,
        "UDP_DECISION_SEQUENCE has incompatible map flags 0x{:x}",
        info.map_flags
    );
    anyhow::ensure!(
        info.btf_id != 0 && info.btf_value_type_id != 0,
        "UDP_DECISION_SEQUENCE is missing value BTF"
    );
    Ok(())
}

fn validate_udp_decision_sequence_value(sequence: UdpDecisionSequence) -> anyhow::Result<()> {
    anyhow::ensure!(
        sequence.next <= honk_ebpf_common::NFQUEUE_TOKEN_MASK,
        "UDP_DECISION_SEQUENCE next token exceeds its token space"
    );
    anyhow::ensure!(
        sequence.exhausted <= 1,
        "UDP_DECISION_SEQUENCE has invalid exhausted flag {}",
        sequence.exhausted
    );
    if sequence.exhausted != 0 {
        anyhow::ensure!(
            sequence.next == honk_ebpf_common::NFQUEUE_TOKEN_MASK,
            "UDP_DECISION_SEQUENCE has an inconsistent exhausted flag"
        );
    }
    Ok(())
}

fn validate_udp_decision_sequence_fd(fd: RawFd) -> anyhow::Result<UdpDecisionSequence> {
    let info = raw_map_info(fd)?;
    validate_udp_decision_sequence_info(&info)?;
    let sequence = locked_udp_decision_sequence(fd)?;
    validate_udp_decision_sequence_value(sequence)?;
    Ok(sequence)
}

pub fn validate_pinned_udp_decision_sequence(path: &Path) -> anyhow::Result<()> {
    let map = aya::maps::MapData::from_pin(path)
        .map_err(|error| anyhow::anyhow!("open persistent map '{}': {error}", path.display()))?;
    validate_udp_decision_sequence_fd(map.fd().as_fd().as_raw_fd()).map(|_| ())
}

pub fn validate_loaded_udp_decision_sequence(bpf: &Ebpf) -> anyhow::Result<UdpDecisionSequence> {
    validate_udp_decision_sequence_fd(map_fd(bpf, super::super::UDP_DECISION_SEQUENCE_MAP)?)
}

#[cfg(test)]
pub(super) fn read_udp_decision_sequence_locked(bpf: &Ebpf) -> anyhow::Result<UdpDecisionSequence> {
    locked_udp_decision_sequence(map_fd(bpf, super::super::UDP_DECISION_SEQUENCE_MAP)?)
}

pub fn reset_udp_decision_sequence_locked(bpf: &Ebpf, generation: u32) -> anyhow::Result<()> {
    let value = UdpDecisionSequence {
        next: generation << honk_ebpf_common::UDP_DECISION_GENERATION_SHIFT,
        ..Default::default()
    };
    update_locked_udp_decision_sequence(
        map_fd(bpf, super::super::UDP_DECISION_SEQUENCE_MAP)?,
        &value,
    )
}

#[cfg(test)]
pub(super) fn write_udp_decision_sequence_locked(
    bpf: &Ebpf,
    value: &UdpDecisionSequence,
) -> anyhow::Result<()> {
    update_locked_udp_decision_sequence(
        map_fd(bpf, super::super::UDP_DECISION_SEQUENCE_MAP)?,
        value,
    )
}

pub fn bpf_lookup_and_delete<K: Pod, V: Pod>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    key: &K,
) -> anyhow::Result<LookupAndDelete<V>> {
    if cap.is_unsupported() {
        return Ok(LookupAndDelete::Unsupported);
    }
    let fd = map_fd(bpf, map)?;
    let mut value = MaybeUninit::<V>::uninit();
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = key as *const K as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = value.as_mut_ptr() as u64;
    let result = unsafe { bpf_syscall(BPF_MAP_LOOKUP_AND_DELETE_ELEM as c_long, &mut attr) };
    if !cap.observe(result) {
        debug!(
            "bpf lookup_and_delete({}) unsupported, using lookup+delete",
            map
        );
        return Ok(LookupAndDelete::Unsupported);
    }
    match result {
        Ok(()) => Ok(LookupAndDelete::Value(unsafe { value.assume_init() })),
        Err(ENOENT) => Ok(LookupAndDelete::Missing),
        Err(error) => Err(anyhow::anyhow!(
            "bpf lookup_and_delete({map}) errno={error}"
        )),
    }
}

/// Delete through a shared Aya map handle. This is only used by the legacy
/// fallback for `routing_handoff_take`, whose public contract deliberately
/// takes `&self` so hot-path callers can retain a backend read lock.
pub fn bpf_delete_shared<K: Pod>(bpf: &Ebpf, map: &str, key: &K) -> anyhow::Result<()> {
    let fd = map_fd(bpf, map)?;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = key as *const K as u64;
    match unsafe { bpf_syscall(BPF_MAP_DELETE_ELEM as c_long, &mut attr) } {
        Ok(()) | Err(ENOENT) => Ok(()),
        Err(error) => Err(anyhow::anyhow!("bpf delete({map}) errno={error}")),
    }
}

fn lookup_batch_result(result: Result<(), c_long>, count: u32) -> Result<(usize, bool), c_long> {
    match result {
        Ok(()) => Ok(((count as usize).min(BPF_BATCH_CHUNK), false)),
        Err(ENOENT) => Ok(((count as usize).min(BPF_BATCH_CHUNK), true)),
        Err(error) => Err(error),
    }
}

fn uninitialized<T>(len: usize) -> Vec<MaybeUninit<T>> {
    std::iter::repeat_with(MaybeUninit::uninit)
        .take(len)
        .collect()
}

fn append_initialized<K: Pod, V: Pod>(
    keys: &[MaybeUninit<K>],
    values: &[MaybeUninit<V>],
    count: usize,
    out: &mut Vec<(K, V)>,
) {
    for index in 0..count {
        out.push((unsafe { keys[index].assume_init() }, unsafe {
            values[index].assume_init()
        }));
    }
}

/// Scan a hash-family map with `BPF_MAP_LOOKUP_BATCH` (Linux 5.6+).
/// Returns `false` without changing `out` when the command is unsupported.
pub fn bpf_lookup_batch_scan<K: Pod, V: Pod>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    out: &mut Vec<(K, V)>,
) -> anyhow::Result<bool> {
    if cap.is_unsupported() {
        return Ok(false);
    }
    let fd = map_fd(bpf, map)?;
    let initial_len = out.len();
    let mut keys = uninitialized::<K>(BPF_BATCH_CHUNK);
    let mut values = uninitialized::<V>(BPF_BATCH_CHUNK);
    let mut next_key = MaybeUninit::<K>::uninit();
    let mut previous_key: Option<K> = None;
    loop {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.batch.map_fd = fd as u32;
        attr.batch.in_batch = previous_key
            .as_ref()
            .map_or(0, |key| key as *const K as u64);
        attr.batch.out_batch = next_key.as_mut_ptr() as u64;
        attr.batch.keys = keys.as_mut_ptr() as u64;
        attr.batch.values = values.as_mut_ptr() as u64;
        attr.batch.count = BPF_BATCH_CHUNK as u32;
        let result = unsafe { bpf_syscall(BPF_MAP_LOOKUP_BATCH as c_long, &mut attr) };
        if !cap.observe(result) {
            out.truncate(initial_len);
            debug!(
                "bpf lookup_batch({}) unsupported, using Aya map iteration",
                map
            );
            return Ok(false);
        }
        let (count, terminal) = match lookup_batch_result(result, unsafe { attr.batch.count }) {
            Ok(result) => result,
            Err(error) => {
                out.truncate(initial_len);
                return Err(anyhow::anyhow!("bpf lookup_batch({map}) errno={error}"));
            }
        };
        append_initialized(&keys, &values, count, out);
        // A successful batch may be short; only ENOENT marks the final batch.
        if terminal {
            return Ok(true);
        }
        if count == 0 {
            out.truncate(initial_len);
            anyhow::bail!("bpf lookup_batch({map}) returned an empty nonterminal batch");
        }
        previous_key = Some(unsafe { next_key.assume_init() });
    }
}

/// Streaming lookup-batch variant that keeps memory bounded to one chunk.
pub fn bpf_lookup_batch_scan_cb<K: Pod, V: Pod>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    visit: &mut BatchVisitor<'_, K, V>,
) -> anyhow::Result<bool> {
    if cap.is_unsupported() {
        return Ok(false);
    }
    let fd = map_fd(bpf, map)?;
    let mut keys = uninitialized::<K>(BPF_BATCH_CHUNK);
    let mut values = uninitialized::<V>(BPF_BATCH_CHUNK);
    let mut next_key = MaybeUninit::<K>::uninit();
    let mut previous_key: Option<K> = None;
    let mut chunk = Vec::with_capacity(BPF_BATCH_CHUNK);
    loop {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.batch.map_fd = fd as u32;
        attr.batch.in_batch = previous_key
            .as_ref()
            .map_or(0, |key| key as *const K as u64);
        attr.batch.out_batch = next_key.as_mut_ptr() as u64;
        attr.batch.keys = keys.as_mut_ptr() as u64;
        attr.batch.values = values.as_mut_ptr() as u64;
        attr.batch.count = BPF_BATCH_CHUNK as u32;
        let result = unsafe { bpf_syscall(BPF_MAP_LOOKUP_BATCH as c_long, &mut attr) };
        if !cap.observe(result) {
            debug!(
                "bpf lookup_batch({}) unsupported, using Aya map iteration",
                map
            );
            return Ok(false);
        }
        let (count, terminal) = lookup_batch_result(result, unsafe { attr.batch.count })
            .map_err(|error| anyhow::anyhow!("bpf lookup_batch({map}) errno={error}"))?;
        chunk.clear();
        append_initialized(&keys, &values, count, &mut chunk);
        if !chunk.is_empty() && !visit(&chunk) {
            return Ok(true);
        }
        // A successful batch may be short; only ENOENT marks the final batch.
        if terminal {
            return Ok(true);
        }
        if count == 0 {
            anyhow::bail!("bpf lookup_batch({map}) returned an empty nonterminal batch");
        }
        previous_key = Some(unsafe { next_key.assume_init() });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_sequence_value_stays_compatible_with_rollback_allocator_across_generation_boundary() {
        let mut sequence = UdpDecisionSequence {
            next: udp_decision_token(1, 42).unwrap(),
            ..UdpDecisionSequence::default()
        };
        validate_udp_decision_sequence_value(sequence).unwrap();

        assert_eq!(sequence.exhausted, 0);
        sequence.next += 1;
        assert_eq!(sequence.next, udp_decision_token(1, 43).unwrap());

        sequence.next = udp_decision_token(0, UDP_DECISION_SEQUENCE_MASK).unwrap();
        validate_udp_decision_sequence_value(sequence).unwrap();
        sequence.next += 1;
        assert_eq!(sequence.next, 1 << UDP_DECISION_GENERATION_SHIFT);
        sequence.next += 1;
        assert_eq!(sequence.next, udp_decision_token(1, 1).unwrap());

        let exhausted = UdpDecisionSequence {
            next: NFQUEUE_TOKEN_MASK,
            exhausted: 1,
            ..UdpDecisionSequence::default()
        };
        validate_udp_decision_sequence_value(exhausted).unwrap();
    }

    #[test]
    fn malformed_sequence_values_are_rejected() {
        for malformed in [
            UdpDecisionSequence {
                next: NFQUEUE_TOKEN_MASK + 1,
                ..UdpDecisionSequence::default()
            },
            UdpDecisionSequence {
                exhausted: 2,
                ..UdpDecisionSequence::default()
            },
            UdpDecisionSequence {
                next: UDP_DECISION_SEQUENCE_MASK,
                exhausted: 1,
                ..UdpDecisionSequence::default()
            },
        ] {
            assert!(validate_udp_decision_sequence_value(malformed).is_err());
        }
    }

    #[test]
    fn successful_short_batch_is_not_terminal() {
        for count in [1, BPF_BATCH_CHUNK as u32 - 1] {
            let (returned, terminal) = lookup_batch_result(Ok(()), count).unwrap();
            assert!(!terminal);
            assert_eq!(returned, count as usize);
        }
    }

    #[test]
    fn terminal_enoent_preserves_partial_count() {
        for count in [0, 1, 127, 128, 129, 255] {
            let (returned, terminal) = lookup_batch_result(Err(ENOENT), count).unwrap();
            assert!(terminal);
            assert_eq!(returned, (count as usize).min(BPF_BATCH_CHUNK));
        }
    }

    fn compatible_sequence_info() -> bpf_map_info {
        let mut info: bpf_map_info = unsafe { core::mem::zeroed() };
        info.type_ = bpf_map_type::BPF_MAP_TYPE_ARRAY as u32;
        info.key_size = core::mem::size_of::<u32>() as u32;
        info.value_size = core::mem::size_of::<UdpDecisionSequence>() as u32;
        info.max_entries = 1;
        info.btf_id = 1;
        info.btf_value_type_id = 2;
        info
    }

    #[test]
    fn persistent_sequence_shape_must_match_exactly() {
        let info = compatible_sequence_info();
        validate_udp_decision_sequence_info(&info).unwrap();

        let mut wrong = info;
        wrong.value_size += 4;
        assert!(validate_udp_decision_sequence_info(&wrong).is_err());
        let mut wrong = info;
        wrong.max_entries = 2;
        assert!(validate_udp_decision_sequence_info(&wrong).is_err());
        let mut wrong = info;
        wrong.map_flags = 1;
        assert!(validate_udp_decision_sequence_info(&wrong).is_err());
        let mut wrong = info;
        wrong.btf_value_type_id = 0;
        assert!(validate_udp_decision_sequence_info(&wrong).is_err());
    }
}
