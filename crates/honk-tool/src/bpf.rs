//! `honk-tool bpf` — quick reads of the running engine's pinned eBPF maps.
//!
//! Maps live at `<pin-root>/<NAME>` (default `/sys/fs/bpf`).  These commands
//! open them via raw `bpf(2)` calls and decode the wire structs — no aya, no
//! program loading, no attach.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::Args;
use honk_ebpf_common::conn::ConnState;
use honk_ebpf_common::dae_ip::In6Addr;
use honk_ebpf_common::redirect_need::{DomainRouting, RoutingHandoffEntry, TuplesKey};
use honk_ebpf_common::{
    OUTBOUND_STATS_MAP_LEN, OutboundStatsCounters, ROUTING_FACT_CAPACITY, ROUTING_POLICY_ROOT_NAME,
    RedirectEntry, RedirectTuple, RoutingPolicyDescriptor,
};

// ---------------------------------------------------------------------------
// Minimal bpf(2) layer (BPF_OBJ_GET / LOOKUP_ELEM / GET_NEXT_KEY).
// ---------------------------------------------------------------------------

const BPF_OBJ_GET: i64 = 7;
const BPF_MAP_LOOKUP_ELEM: i64 = 1;
const BPF_MAP_GET_NEXT_KEY: i64 = 4;
const BPF_MAP_GET_FD_BY_ID: i64 = 14;
const BPF_OBJ_GET_INFO_BY_FD: i64 = 15;

#[repr(C)]
#[derive(Default)]
struct BpfAttr {
    map_fd: u32,
    key: u64,
    value_or_next: u64,
    flags: u64,
    next_key: u64,
}

#[repr(C)]
#[derive(Default)]
struct BpfObjGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

fn bpf(cmd: i64, attr: &mut BpfAttr) -> io::Result<i64> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *mut BpfAttr,
            std::mem::size_of::<BpfAttr>() as u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn bpf_obj_get(path: &Path) -> io::Result<RawFd> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut attr = BpfObjGetAttr {
        pathname: c_path.as_ptr() as u64,
        ..Default::default()
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET,
            &mut attr as *mut BpfObjGetAttr,
            std::mem::size_of::<BpfObjGetAttr>() as u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as RawFd)
    }
}

fn map_lookup(fd: RawFd, key: &[u8], value: &mut [u8]) -> io::Result<bool> {
    let mut attr = BpfAttr {
        map_fd: fd as u32,
        key: key.as_ptr() as u64,
        value_or_next: value.as_mut_ptr() as u64,
        ..Default::default()
    };
    match bpf(BPF_MAP_LOOKUP_ELEM, &mut attr) {
        Ok(_) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(e) => Err(e),
    }
}

fn map_next_key(fd: RawFd, prev: Option<&[u8]>, next: &mut [u8]) -> io::Result<bool> {
    let mut attr = BpfAttr {
        map_fd: fd as u32,
        key: prev.map_or(0, |p| p.as_ptr() as u64),
        value_or_next: next.as_mut_ptr() as u64,
        ..Default::default()
    };
    match bpf(BPF_MAP_GET_NEXT_KEY, &mut attr) {
        Ok(_) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Iterate every entry of a hash-family map as raw (key, value) byte pairs.
fn map_entries(fd: RawFd, key_len: usize, value_len: usize) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut prev: Option<Vec<u8>> = None;
    loop {
        let mut key = vec![0u8; key_len];
        if !map_next_key(fd, prev.as_deref(), &mut key)? {
            break;
        }
        let mut value = vec![0u8; value_len];
        if map_lookup(fd, &key, &mut value)? {
            out.push((key.clone(), value));
        }
        prev = Some(key);
    }
    Ok(out)
}

fn read_value<T: Copy>(fd: RawFd, key: &[u8]) -> io::Result<Option<T>> {
    let mut buf = vec![0u8; std::mem::size_of::<T>()];
    if map_lookup(fd, key, &mut buf)? {
        Ok(Some(unsafe {
            std::ptr::read_unaligned(buf.as_ptr() as *const T)
        }))
    } else {
        Ok(None)
    }
}

fn read_percpu_sum(fd: RawFd, ncpu: usize, index: u32) -> io::Result<u64> {
    let mut buf = vec![0u8; ncpu * 8];
    let mut attr = BpfAttr {
        map_fd: fd as u32,
        key: &index as *const u32 as u64,
        value_or_next: buf.as_mut_ptr() as u64,
        ..Default::default()
    };
    bpf(BPF_MAP_LOOKUP_ELEM, &mut attr)?;
    let mut total = 0u64;
    for chunk in buf.as_chunks::<8>().0 {
        total = total.wrapping_add(u64::from_ne_bytes(*chunk));
    }
    Ok(total)
}

fn read_percpu_outbound(fd: RawFd, ncpu: usize, index: u32) -> io::Result<OutboundStatsCounters> {
    let value_len = std::mem::size_of::<OutboundStatsCounters>();
    let mut buf = vec![0u8; ncpu * value_len];
    let mut attr = BpfAttr {
        map_fd: fd as u32,
        key: &index as *const u32 as u64,
        value_or_next: buf.as_mut_ptr() as u64,
        ..Default::default()
    };
    bpf(BPF_MAP_LOOKUP_ELEM, &mut attr)?;
    Ok(sum_percpu_outbound(&buf))
}

fn sum_percpu_outbound(buf: &[u8]) -> OutboundStatsCounters {
    let value_len = std::mem::size_of::<OutboundStatsCounters>();
    debug_assert_eq!(buf.len() % value_len, 0);
    let mut total = OutboundStatsCounters::default();
    for chunk in buf.chunks_exact(value_len) {
        let value =
            unsafe { std::ptr::read_unaligned(chunk.as_ptr() as *const OutboundStatsCounters) };
        total.wrapping_add_assign(&value);
    }
    total
}

fn possible_cpus() -> usize {
    std::fs::read_dir("/sys/devices/system/cpu")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("cpu"))
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .chars()
                        .nth(3)
                        .is_some_and(|c| c.is_ascii_digit())
                })
                .count()
        })
        .unwrap_or(1)
        .max(1)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct BpfArgs {
    #[command(subcommand)]
    pub command: BpfCommand,
}

#[derive(clap::Subcommand)]
pub enum BpfCommand {
    /// Dump (or point-query) entries of a pinned map.
    Show(ShowArgs),
    /// OUTBOUND_STATS per-outbound counters + conn-state occupancy + overflow.
    Stats(StatsArgs),
}

#[derive(Args)]
pub struct ShowArgs {
    /// Map: conn-state | redirect-track | domain-routing | routing-handoff
    pub map: String,
    /// Only show entries whose src or dst matches this IP.
    #[arg(long)]
    pub ip: Option<IpAddr>,
    /// Max entries to print (0 = all).
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// BPF pin root.
    #[arg(long, default_value = "/sys/fs/bpf")]
    pub pin_root: PathBuf,
}

#[derive(Args)]
pub struct StatsArgs {
    /// BPF pin root.
    #[arg(long, default_value = "/sys/fs/bpf")]
    pub pin_root: PathBuf,
}

pub async fn run(args: BpfArgs) -> anyhow::Result<()> {
    match args.command {
        BpfCommand::Show(a) => show(a),
        BpfCommand::Stats(a) => stats(a),
    }
}

fn ip_of(addr: &In6Addr) -> IpAddr {
    let b = unsafe { addr.u6_addr8 };
    if b[0..10].iter().all(|&x| x == 0) && b[10] == 0xff && b[11] == 0xff {
        IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(b))
    }
}

fn open(pin_root: &Path, name: &str) -> anyhow::Result<RawFd> {
    let path = pin_root.join(name);
    bpf_obj_get(&path).with_context(|| format!("open pinned map {}", path.display()))
}

fn map_by_id(id: u32) -> io::Result<OwnedFd> {
    let attr = [id, 0, 0];
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_GET_FD_BY_ID,
            attr.as_ptr(),
            std::mem::size_of_val(&attr),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) })
    }
}

fn check_map_layout(fd: RawFd, kind: u32, key_size: u32, value_size: u32) -> anyhow::Result<()> {
    #[repr(C)]
    struct InfoAttr {
        fd: u32,
        len: u32,
        info: u64,
    }
    let mut info = [0u32; 6];
    let mut attr = InfoAttr {
        fd: fd as u32,
        len: std::mem::size_of_val(&info) as u32,
        info: info.as_mut_ptr() as u64,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD,
            &mut attr,
            std::mem::size_of::<InfoAttr>(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error().into());
    }
    anyhow::ensure!(
        (info[0], info[2], info[3]) == (kind, key_size, value_size),
        "unexpected routing map layout: type={} key={} value={}",
        info[0],
        info[2],
        info[3]
    );
    Ok(())
}

fn open_domain_map(pin_root: &Path) -> anyhow::Result<OwnedFd> {
    let root = unsafe { OwnedFd::from_raw_fd(open(pin_root, ROUTING_POLICY_ROOT_NAME)?) };
    check_map_layout(root.as_raw_fd(), 12, 4, 4)?;
    let key = 0u32.to_ne_bytes();
    // A generation can retire between reading its ID and acquiring an FD.
    for _ in 0..3 {
        let descriptor_id = read_value::<u32>(root.as_raw_fd(), &key)?
            .context("no routing policy has been published")?;
        let descriptor = match map_by_id(descriptor_id) {
            Ok(fd) => fd,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        check_map_layout(
            descriptor.as_raw_fd(),
            2,
            4,
            std::mem::size_of::<RoutingPolicyDescriptor>() as u32,
        )?;
        let policy = read_value::<RoutingPolicyDescriptor>(descriptor.as_raw_fd(), &key)?
            .context("routing descriptor is empty")?;
        let domain = match map_by_id(policy.domain_map_id) {
            Ok(fd) => fd,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        check_map_layout(
            domain.as_raw_fd(),
            1,
            16,
            std::mem::size_of::<DomainRouting>() as u32,
        )?;
        return Ok(domain);
    }
    anyhow::bail!("routing changed while opening the domain map; retry the command")
}

fn matches_ip(key: &TuplesKey, ip: &Option<IpAddr>) -> bool {
    match ip {
        None => true,
        Some(want) => ip_of(&key.src_ip) == *want || ip_of(&key.dst_ip) == *want,
    }
}

fn show(args: ShowArgs) -> anyhow::Result<()> {
    match args.map.as_str() {
        "conn-state" => {
            let fd = open(&args.pin_root, "CONN_STATE_MAP")?;
            let entries = map_entries(
                fd,
                std::mem::size_of::<TuplesKey>(),
                std::mem::size_of::<ConnState>(),
            )?;
            let mut shown = 0usize;
            for (kb, vb) in &entries {
                let k: TuplesKey = unsafe { std::ptr::read_unaligned(kb.as_ptr() as *const _) };
                let v: ConnState = unsafe { std::ptr::read_unaligned(vb.as_ptr() as *const _) };
                if !matches_ip(&k, &args.ip) || (args.limit > 0 && shown >= args.limit) {
                    continue;
                }
                shown += 1;
                println!(
                    "{:?} {}:{} -> {}:{} out={} mark=0x{:x} must={} state={} seen={}",
                    k.l4proto,
                    ip_of(&k.src_ip),
                    k.src_port,
                    ip_of(&k.dst_ip),
                    k.dst_port,
                    unsafe { v.meta.data.outbound },
                    unsafe { v.meta.data.mark },
                    unsafe { v.meta.data.must },
                    v.state,
                    v.last_seen_ns
                );
            }
            println!("-- {shown}/{} entries", entries.len());
        }
        "redirect-track" => {
            let fd = open(&args.pin_root, "REDIRECT_TRACK")?;
            let entries = map_entries(
                fd,
                std::mem::size_of::<RedirectTuple>(),
                std::mem::size_of::<RedirectEntry>(),
            )?;
            let mut shown = 0usize;
            for (kb, vb) in &entries {
                let k: RedirectTuple = unsafe { std::ptr::read_unaligned(kb.as_ptr() as *const _) };
                let v: RedirectEntry = unsafe { std::ptr::read_unaligned(vb.as_ptr() as *const _) };
                if let Some(want) = &args.ip
                    && ip_of(&k.src_ip) != *want
                    && ip_of(&k.dst_ip) != *want
                {
                    continue;
                }
                if args.limit > 0 && shown >= args.limit {
                    continue;
                }
                shown += 1;
                println!(
                    "{} -> {} out={} from_wan={} ifindex={} seen={}",
                    ip_of(&k.src_ip),
                    ip_of(&k.dst_ip),
                    v.outbound,
                    v.from_wan,
                    v.ifindex,
                    v.last_seen_ns
                );
            }
            println!("-- {shown}/{} entries", entries.len());
        }
        "domain-routing" => {
            let fd = open_domain_map(&args.pin_root)?;
            let entries = map_entries(fd.as_raw_fd(), 16, std::mem::size_of::<DomainRouting>())?;
            let mut shown = 0usize;
            for (kb, vb) in &entries {
                let mut addr: In6Addr = unsafe { std::mem::zeroed() };
                unsafe { addr.u6_addr8.copy_from_slice(kb) };
                let v: DomainRouting = unsafe { std::ptr::read_unaligned(vb.as_ptr() as *const _) };
                let ip = ip_of(&addr);
                if let Some(want) = &args.ip
                    && ip != *want
                {
                    continue;
                }
                if args.limit > 0 && shown >= args.limit {
                    continue;
                }
                shown += 1;
                let predicates: Vec<u32> = (0..ROUTING_FACT_CAPACITY as u32)
                    .filter(|i| v.bitmap[(i / 32) as usize] & (1 << (i % 32)) != 0)
                    .collect();
                println!("{ip} predicates={predicates:?}");
            }
            println!("-- {shown}/{} entries", entries.len());
        }
        "routing-handoff" => {
            let fd = open(&args.pin_root, "ROUTING_HANDOFF_MAP")?;
            let entries = map_entries(
                fd,
                std::mem::size_of::<TuplesKey>(),
                std::mem::size_of::<RoutingHandoffEntry>(),
            )?;
            let mut shown = 0usize;
            for (kb, vb) in &entries {
                let k: TuplesKey = unsafe { std::ptr::read_unaligned(kb.as_ptr() as *const _) };
                let v: RoutingHandoffEntry =
                    unsafe { std::ptr::read_unaligned(vb.as_ptr() as *const _) };
                if !matches_ip(&k, &args.ip) || (args.limit > 0 && shown >= args.limit) {
                    continue;
                }
                shown += 1;
                println!(
                    "{:?} {}:{} -> {}:{} out={} mark=0x{:x} must={} seen={}",
                    k.l4proto,
                    ip_of(&k.src_ip),
                    k.src_port,
                    ip_of(&k.dst_ip),
                    k.dst_port,
                    v.result.outbound,
                    v.result.mark,
                    v.result.must,
                    v.last_seen_ns
                );
            }
            println!("-- {shown}/{} entries", entries.len());
        }
        other => anyhow::bail!(
            "unknown map '{other}' (conn-state | redirect-track | domain-routing | routing-handoff)"
        ),
    }
    Ok(())
}

pub(crate) fn stats(args: StatsArgs) -> anyhow::Result<()> {
    let ncpu = possible_cpus();

    let fd = open(&args.pin_root, "BPF_STATS_MAP")?;
    let udp_ovf: u64 = read_value(fd, &0u32.to_ne_bytes())?.unwrap_or(0);
    let tcp_ovf: u64 = read_value(fd, &1u32.to_ne_bytes())?.unwrap_or(0);
    println!("conn-state overflow: udp={udp_ovf} tcp={tcp_ovf}");
    let redirect_failures: u64 = read_value(fd, &2u32.to_ne_bytes())?.unwrap_or(0);
    let handoff_failures: u64 = read_value(fd, &3u32.to_ne_bytes())?.unwrap_or(0);
    let cookie_failures: u64 = read_value(fd, &4u32.to_ne_bytes())?.unwrap_or(0);
    println!(
        "auxiliary insert failures: redirect_track={redirect_failures} \
         routing_handoff={handoff_failures} cookie_pid={cookie_failures}"
    );

    let fd = open(&args.pin_root, "CONN_STATE_OCCUPANCY")?;
    let inserts = read_percpu_sum(fd, ncpu, 0)?;
    let deletes = read_percpu_sum(fd, ncpu, 1)?;
    println!(
        "conn-state occupancy: inserts={inserts} ebpf_deletes={deletes} raw_live={}",
        inserts.saturating_sub(deletes)
    );

    let fd = open(&args.pin_root, "OUTBOUND_STATS")?;
    println!("\noutbound counters (tx_pkts tx_bytes rx_pkts rx_bytes):");
    for outbound in 0..OUTBOUND_STATS_MAP_LEN {
        let counters = read_percpu_outbound(fd, ncpu, outbound)?;
        if counters.tx_packets != 0
            || counters.tx_bytes != 0
            || counters.rx_packets != 0
            || counters.rx_bytes != 0
        {
            println!(
                "  outbound {outbound:<4} {} {} {} {}",
                counters.tx_packets, counters.tx_bytes, counters.rx_packets, counters.rx_bytes
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(counters: OutboundStatsCounters) -> Vec<u8> {
        [
            counters.tx_packets.to_ne_bytes(),
            counters.tx_bytes.to_ne_bytes(),
            counters.rx_packets.to_ne_bytes(),
            counters.rx_bytes.to_ne_bytes(),
        ]
        .concat()
    }

    #[test]
    fn sums_packed_outbound_counters_across_cpus() {
        let mut values = encode(OutboundStatsCounters {
            tx_packets: 1,
            tx_bytes: 20,
            rx_packets: 3,
            rx_bytes: 40,
        });
        values.extend(encode(OutboundStatsCounters {
            tx_packets: 5,
            tx_bytes: 60,
            rx_packets: 7,
            rx_bytes: 80,
        }));

        let total = sum_percpu_outbound(&values);
        assert_eq!(total.tx_packets, 6);
        assert_eq!(total.tx_bytes, 80);
        assert_eq!(total.rx_packets, 10);
        assert_eq!(total.rx_bytes, 120);
    }
}
