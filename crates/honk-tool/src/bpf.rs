//! `honk-tool bpf` — pinned-map reads and opt-in WAN diagnostic capture.
//!
//! Maps live at `<pin-root>/<NAME>` (default `/sys/fs/bpf`).  These commands
//! open them via raw `bpf(2)` calls and decode the wire structs — no aya, no
//! program loading, no attach.
//! Only `wan-diag` writes, and only to its diagnostic filter map.

mod wan;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::Args;
use honk_core::ebpf::map_snapshot::{self, BatchError, BatchSpec};
use honk_ebpf_common::conn::{BpfStatsKey, ConnState};
use honk_ebpf_common::dae_ip::In6Addr;
use honk_ebpf_common::redirect_need::{DomainRouting, RoutingHandoffEntry, TuplesKey};
use honk_ebpf_common::{
    FlowMapValue, OUTBOUND_STATS_MAP_LEN, OutboundStatsCounters, ROUTING_FACT_CAPACITY,
    ROUTING_POLICY_ROOT_NAME, RedirectEntry, RedirectTuple, RoutingPolicyDescriptor,
};

// ---------------------------------------------------------------------------
// Minimal bpf(2) layer (object metadata, singleton reads and batch snapshots).
// ---------------------------------------------------------------------------

const BPF_OBJ_GET: i64 = 7;
const BPF_MAP_LOOKUP_ELEM: i64 = 1;
const BPF_MAP_GET_NEXT_KEY: i64 = 4;
const BPF_MAP_GET_FD_BY_ID: i64 = 14;
const BPF_OBJ_GET_INFO_BY_FD: i64 = 15;
const BPF_F_LOCK: u64 = 4;
const BPF_BATCH_CHUNK: usize = 64;

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

fn bpf<T>(cmd: i64, attr: &mut T) -> io::Result<i64> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *mut T,
            std::mem::size_of::<T>() as u32,
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

fn flow_payload<T: Copy>(bytes: &[u8]) -> T {
    assert_eq!(bytes.len(), std::mem::size_of::<FlowMapValue<T>>());
    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const FlowMapValue<T>).value }
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

fn read_percpu_sum(fd: RawFd, buf: &mut [u8], index: u32) -> io::Result<u64> {
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

fn read_percpu_outbound(
    fd: RawFd,
    buf: &mut [u8],
    index: u32,
) -> io::Result<OutboundStatsCounters> {
    let mut attr = BpfAttr {
        map_fd: fd as u32,
        key: &index as *const u32 as u64,
        value_or_next: buf.as_mut_ptr() as u64,
        ..Default::default()
    };
    bpf(BPF_MAP_LOOKUP_ELEM, &mut attr)?;
    Ok(sum_percpu_outbound(buf))
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

fn parse_possible_cpus(input: &str) -> anyhow::Result<usize> {
    let input = input.trim();
    anyhow::ensure!(!input.is_empty(), "possible CPU list is empty");

    let mut count = 0usize;
    let mut previous_end = None;
    for term in input.split(',') {
        anyhow::ensure!(!term.is_empty(), "possible CPU list contains an empty term");

        let (start, end) = match term.split_once('-') {
            Some((start, end)) => (parse_cpu_id(start)?, parse_cpu_id(end)?),
            None => {
                let id = parse_cpu_id(term)?;
                (id, id)
            }
        };
        anyhow::ensure!(start <= end, "possible CPU range {term:?} is descending");
        if let Some(previous_end) = previous_end {
            anyhow::ensure!(
                start > previous_end,
                "possible CPU ranges are overlapping or out of order at {term:?}"
            );
        }
        let range_count = end
            .checked_sub(start)
            .and_then(|count| count.checked_add(1))
            .context("possible CPU range count overflow")?;
        count = count
            .checked_add(range_count)
            .context("possible CPU population count overflow")?;
        previous_end = Some(end);
    }
    Ok(count)
}

fn parse_cpu_id(value: &str) -> anyhow::Result<usize> {
    anyhow::ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "possible CPU ID {value:?} is not a decimal number"
    );
    anyhow::ensure!(
        value == "0" || !value.starts_with('0'),
        "possible CPU ID {value:?} is not canonical"
    );
    value
        .parse()
        .with_context(|| format!("possible CPU ID {value:?} overflows"))
}

fn percpu_buffer_len(count: usize, value_size: usize) -> anyhow::Result<usize> {
    let stride = value_size
        .checked_add(7)
        .context("per-CPU value stride overflow")?
        & !7;
    let bytes = count
        .checked_mul(stride)
        .context("per-CPU buffer length overflow")?;
    anyhow::ensure!(
        bytes <= isize::MAX as usize,
        "per-CPU buffer length {bytes} exceeds isize::MAX"
    );
    Ok(bytes)
}

fn possible_cpus(cpu_root: &Path) -> anyhow::Result<usize> {
    let path = cpu_root.join("possible");
    let input = std::fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("read possible CPU file {}: {error}", path.display()))?;
    parse_possible_cpus(&input)
        .map_err(|error| anyhow::anyhow!("parse possible CPU file {}: {error}", path.display()))
}

struct PerCpuStats {
    occupancy_fd: OwnedFd,
    occupancy: Vec<u8>,
    outbound_fd: OwnedFd,
    outbound: Vec<u8>,
}

fn prepare_percpu_stats<F>(
    cpu_root: &Path,
    print_ordinary: impl FnOnce() -> anyhow::Result<()>,
    mut open_info: F,
) -> anyhow::Result<PerCpuStats>
where
    F: FnMut(&str) -> anyhow::Result<(OwnedFd, [u32; 6])>,
{
    let ncpu = possible_cpus(cpu_root)?;
    let occupancy_len = percpu_buffer_len(ncpu, 8)?;
    let outbound_len = percpu_buffer_len(ncpu, std::mem::size_of::<OutboundStatsCounters>())?;

    print_ordinary()?;

    let (occupancy_fd, occupancy_info) =
        open_info("CONN_STATE_OCCUPANCY").context("open/query map CONN_STATE_OCCUPANCY")?;
    check_map_layout("CONN_STATE_OCCUPANCY", occupancy_info, 6, 4, 8)?;
    let (outbound_fd, outbound_info) =
        open_info("OUTBOUND_STATS").context("open/query map OUTBOUND_STATS")?;
    check_map_layout(
        "OUTBOUND_STATS",
        outbound_info,
        6,
        4,
        std::mem::size_of::<OutboundStatsCounters>() as u32,
    )?;

    Ok(PerCpuStats {
        occupancy_fd,
        occupancy: vec![0u8; occupancy_len],
        outbound_fd,
        outbound: vec![0u8; outbound_len],
    })
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
    /// Capture issue #415 WAN evidence as JSON, without bpftool.
    WanDiag(wan::Args),
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
        BpfCommand::WanDiag(a) => wan::run(a).await,
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

/// # Safety
/// `T` must be an initialized BPF info prefix whose fields accept every bit pattern.
unsafe fn object_info<T>(fd: RawFd, info: &mut T) -> io::Result<()> {
    #[repr(C)]
    struct InfoAttr {
        fd: u32,
        len: u32,
        info: u64,
    }
    let mut attr = InfoAttr {
        fd: fd as u32,
        len: std::mem::size_of::<T>() as u32,
        info: info as *mut T as u64,
    };
    bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr).map(|_| ())
}

fn map_info(fd: RawFd, map_name: &str) -> anyhow::Result<[u32; 6]> {
    let mut info = [0u32; 6];
    unsafe { object_info(fd, &mut info) }
        .with_context(|| format!("query metadata for map {map_name}"))?;
    Ok(info)
}

fn check_map_layout(
    map_name: &str,
    info: [u32; 6],
    kind: u32,
    key_size: u32,
    value_size: u32,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        (info[0], info[2], info[3]) == (kind, key_size, value_size),
        "unexpected map layout for {map_name}: expected type={kind} key={key_size} value={value_size}, actual type={} key={} value={}",
        info[0],
        info[2],
        info[3]
    );
    Ok(())
}

fn query_map_layout(
    fd: RawFd,
    map_name: &str,
    kind: u32,
    key_size: u32,
    value_size: u32,
) -> anyhow::Result<()> {
    let info = map_info(fd, map_name)?;
    check_map_layout(map_name, info, kind, key_size, value_size)
}

fn open_domain_map(pin_root: &Path) -> anyhow::Result<OwnedFd> {
    let root = unsafe { OwnedFd::from_raw_fd(open(pin_root, ROUTING_POLICY_ROOT_NAME)?) };
    query_map_layout(root.as_raw_fd(), ROUTING_POLICY_ROOT_NAME, 12, 4, 4)?;
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
        query_map_layout(
            descriptor.as_raw_fd(),
            "routing policy descriptor",
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
        query_map_layout(
            domain.as_raw_fd(),
            "domain routing",
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

fn batch_error(error: BatchError, elem_flags: u64) -> io::Error {
    match error {
        BatchError::Errno { errno, .. }
            if matches!(errno, libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) =>
        {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "safe external map snapshot requires BPF_MAP_LOOKUP_BATCH with elem_flags={elem_flags:#x}: {}",
                    io::Error::from_raw_os_error(errno)
                ),
            )
        }
        BatchError::Errno { errno, .. } => io::Error::from_raw_os_error(errno),
        BatchError::InvalidCount { count, terminal } => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("BPF_MAP_LOOKUP_BATCH returned invalid count {count} (terminal={terminal})"),
        ),
    }
}

fn flow_entries<K: Copy, V: Copy>(args: &ShowArgs, name: &str) -> anyhow::Result<Vec<(K, V)>> {
    let fd = open(&args.pin_root, name)?;
    let (key_len, value_len) = (
        std::mem::size_of::<K>(),
        std::mem::size_of::<FlowMapValue<V>>(),
    );
    query_map_layout(fd, name, 1, key_len as u32, value_len as u32)?;
    let mut entries = Vec::new();
    let visit = |keys: &[u8], values: &[u8]| {
        entries.extend(
            keys.chunks_exact(key_len)
                .zip(values.chunks_exact(value_len))
                .map(|(key, value)| {
                    (
                        unsafe { std::ptr::read_unaligned(key.as_ptr() as *const K) },
                        flow_payload(value),
                    )
                }),
        );
        true
    };
    unsafe {
        map_snapshot::scan(
            BatchSpec {
                fd,
                key_len,
                value_len,
                chunk: BPF_BATCH_CHUNK,
                elem_flags: BPF_F_LOCK,
            },
            &mut None,
            |_, _| true,
            visit,
        )
    }
    .map_err(|error| batch_error(error, BPF_F_LOCK))?;
    Ok(entries)
}

fn show(args: ShowArgs) -> anyhow::Result<()> {
    match args.map.as_str() {
        "conn-state" => {
            let entries = flow_entries::<TuplesKey, ConnState>(&args, "CONN_STATE_MAP")?;
            let mut shown = 0usize;
            for (k, v) in &entries {
                if !matches_ip(k, &args.ip) || (args.limit > 0 && shown >= args.limit) {
                    continue;
                }
                shown += 1;
                println!(
                    "{:?} {}:{} -> {}:{} out={} mark=0x{:x} must={} state={} seen={} trace={}",
                    k.l4proto,
                    ip_of(&k.src_ip),
                    k.src_port,
                    ip_of(&k.dst_ip),
                    k.dst_port,
                    unsafe { v.meta.data.outbound },
                    unsafe { v.meta.data.mark },
                    unsafe { v.meta.data.must },
                    v.state,
                    v.last_seen_ns,
                    v.trace_id
                );
            }
            println!("-- {shown}/{} entries", entries.len());
        }
        "redirect-track" => {
            let entries = flow_entries::<RedirectTuple, RedirectEntry>(&args, "REDIRECT_TRACK")?;
            let mut shown = 0usize;
            for (k, v) in &entries {
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
            let entries =
                flow_entries::<TuplesKey, RoutingHandoffEntry>(&args, "ROUTING_HANDOFF_MAP")?;
            let mut shown = 0usize;
            for (k, v) in &entries {
                if !matches_ip(k, &args.ip) || (args.limit > 0 && shown >= args.limit) {
                    continue;
                }
                shown += 1;
                println!(
                    "{:?} {}:{} -> {}:{} out={} mark=0x{:x} must={} seen={} generation={} trace={}",
                    k.l4proto,
                    ip_of(&k.src_ip),
                    k.src_port,
                    ip_of(&k.dst_ip),
                    k.dst_port,
                    v.result.outbound,
                    v.result.mark,
                    v.result.must,
                    v.last_seen_ns,
                    v.routing_generation,
                    v.trace_id
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

fn print_ordinary_stats(pin_root: &Path) -> anyhow::Result<()> {
    let fd = unsafe { OwnedFd::from_raw_fd(open(pin_root, "BPF_STATS_MAP")?) };
    let info = map_info(fd.as_raw_fd(), "BPF_STATS_MAP")?;
    print_ordinary_stats_with(
        info,
        |key| read_value(fd.as_raw_fd(), key),
        io::stdout().lock(),
    )
}

// A map from an engine with different key numbering would print counters under wrong labels.
fn print_ordinary_stats_with(
    info: [u32; 6],
    mut read: impl FnMut(&[u8]) -> io::Result<Option<u64>>,
    mut output: impl io::Write,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        info[4] == BpfStatsKey::COUNT,
        "unexpected map layout for BPF_STATS_MAP: expected max_entries={} found {}; \
         the running engine and honk-tool disagree on the statistics keys",
        BpfStatsKey::COUNT,
        info[4]
    );
    for key in BpfStatsKey::ALL {
        let value = read(&(key as u32).to_ne_bytes())?.unwrap_or(0);
        writeln!(output, "{}: {value}", key.label())?;
    }
    Ok(())
}

pub(crate) fn stats(args: StatsArgs) -> anyhow::Result<()> {
    let mut percpu = prepare_percpu_stats(
        Path::new("/sys/devices/system/cpu"),
        || print_ordinary_stats(&args.pin_root),
        |name| {
            let fd = unsafe { OwnedFd::from_raw_fd(open(&args.pin_root, name)?) };
            let info = map_info(fd.as_raw_fd(), name)?;
            Ok((fd, info))
        },
    )?;

    let inserts = read_percpu_sum(percpu.occupancy_fd.as_raw_fd(), &mut percpu.occupancy, 0)?;
    let deletes = read_percpu_sum(percpu.occupancy_fd.as_raw_fd(), &mut percpu.occupancy, 1)?;
    println!(
        "conn-state occupancy: inserts={inserts} ebpf_deletes={deletes} raw_live={}",
        inserts.saturating_sub(deletes)
    );

    println!("\noutbound counters (tx_pkts tx_bytes rx_pkts rx_bytes):");
    for outbound in 0..OUTBOUND_STATS_MAP_LEN {
        let counters = read_percpu_outbound(
            percpu.outbound_fd.as_raw_fd(),
            &mut percpu.outbound,
            outbound,
        )?;
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
mod tests;
