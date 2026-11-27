use aya::Ebpf;
use aya::maps::{Map, MapData};
use aya_obj::generated::{bpf_attr, bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, bpf_map_info, bpf_map_type};
use std::ffi::c_long;
use std::os::fd::{AsFd, AsRawFd, RawFd};

pub(crate) unsafe fn bpf_syscall(cmd: c_long, attr: &mut bpf_attr) -> Result<c_long, c_long> {
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
        Ok(ret)
    }
}

pub(crate) fn map_data(map: &Map) -> &MapData {
    match map {
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
    }
}

pub(in crate::ebpf) fn map_raw_fd(map: &Map) -> RawFd {
    map_data(map).fd().as_fd().as_raw_fd()
}

pub(crate) fn raw_map_info(fd: RawFd) -> anyhow::Result<bpf_map_info> {
    let mut info: bpf_map_info = unsafe { core::mem::zeroed() };
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.info.bpf_fd = fd as u32;
    attr.info.info_len = core::mem::size_of::<bpf_map_info>() as u32;
    attr.info.info = (&mut info as *mut bpf_map_info) as u64;
    unsafe { bpf_syscall(BPF_OBJ_GET_INFO_BY_FD as c_long, &mut attr) }
        .map_err(|error| anyhow::anyhow!("BPF_OBJ_GET_INFO_BY_FD errno={error}"))?;
    Ok(info)
}

pub(crate) fn validate_map_layout(
    bpf: &Ebpf,
    name: &str,
    type_: bpf_map_type,
    key: u32,
    value: u32,
    entries: u32,
    flags: u32,
) -> anyhow::Result<()> {
    let map = bpf
        .map(name)
        .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))?;
    let info = raw_map_info(map_raw_fd(map))?;
    anyhow::ensure!(
        info.type_ == type_ as u32
            && info.key_size == key
            && info.value_size == value
            && info.max_entries == entries
            && info.map_flags == flags,
        "map '{name}' has incompatible lifetime layout: type={} key={} value={} entries={} flags={}",
        info.type_,
        info.key_size,
        info.value_size,
        info.max_entries,
        info.map_flags
    );
    Ok(())
}
