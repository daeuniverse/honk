use super::*;
use honk_ebpf_common::wan_diagnostic::{FILTER_MAP, Filter, Reason, SAMPLE_MAP, Sample};
use serde_json::{Value, json};
use std::io::Write;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::signal::unix::{SignalKind, signal};

const BPF_MAP_UPDATE_ELEM: i64 = 2;
const BPF_PROG_GET_FD_BY_ID: i64 = 13;
const BPF_PROG_QUERY: i64 = 16;
const BPF_TCX_EGRESS: u32 = 47;

#[derive(clap::Args)]
pub struct Args {
    /// WAN interface in this network namespace.
    #[arg(long)]
    interface: String,
    /// Exact probe source port; run only one collector at a time.
    #[arg(long, required_unless_present = "disable", conflicts_with = "disable",
        value_parser = clap::value_parser!(u16).range(1..))]
    source_port: Option<u16>,
    /// Enabled sampling interval (1..300 seconds).
    #[arg(long, default_value_t = 15, conflicts_with = "disable",
        value_parser = clap::value_parser!(u64).range(1..=300))]
    seconds: u64,
    /// Disable this diagnostic filter, including recovery after SIGKILL.
    #[arg(long)]
    disable: bool,
    /// BPF pin root of the diagnostic honk-core.
    #[arg(long, default_value = "/sys/fs/bpf")]
    pin_root: PathBuf,
}

#[repr(C)]
#[derive(Default)]
struct Query {
    ifindex: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    program_ids: u64,
    count: u32,
    padding: u32,
    program_flags: u64,
    link_ids: u64,
    link_flags: u64,
    revision: u64,
}

#[repr(C)]
#[derive(Default)]
struct ProgramInfo {
    kind: u32,
    id: u32,
    tag: [u8; 8],
    jited_len: u32,
    translated_len: u32,
    jited_insns: u64,
    translated_insns: u64,
    load_time: u64,
    uid: u32,
    map_count: u32,
    map_ids: u64,
}

#[repr(C)]
#[derive(Default)]
struct MapInfo {
    layout: [u32; 6],
    name: [u8; 16],
}

const _: () = assert!(size_of::<Query>() == 64);
const _: () = assert!(std::mem::offset_of!(Query, link_ids) == 40);
const _: () = assert!(std::mem::offset_of!(Query, count) == 24);
const _: () = assert!(std::mem::offset_of!(Query, revision) == 56);
const _: () = assert!(size_of::<ProgramInfo>() == 64);
const _: () = assert!(std::mem::offset_of!(ProgramInfo, map_ids) == 56);
const _: () = assert!(std::mem::offset_of!(ProgramInfo, map_count) == 52);
const _: () = assert!(size_of::<MapInfo>() == 40);

fn chain(ifindex: u32) -> anyhow::Result<Vec<(u32, u32)>> {
    let mut programs = [0u32; 64];
    let mut links = [0u32; 64];
    let mut query = Query {
        ifindex,
        attach_type: BPF_TCX_EGRESS,
        program_ids: programs.as_mut_ptr() as u64,
        count: programs.len() as u32,
        link_ids: links.as_mut_ptr() as u64,
        ..Default::default()
    };
    bpf(BPF_PROG_QUERY, &mut query).context("query TCX egress (at most 64 attachments)")?;
    let count = query.count as usize;
    anyhow::ensure!(
        count <= programs.len(),
        "TCX egress exceeds diagnostic capacity"
    );
    Ok(programs[..count]
        .iter()
        .copied()
        .zip(links[..count].iter().copied())
        .collect())
}

fn open_map(
    root: &Path,
    name: &str,
    kind: u32,
    size: usize,
    entries: usize,
) -> anyhow::Result<(OwnedFd, u32)> {
    let fd = unsafe { OwnedFd::from_raw_fd(open(root, name)?) };
    let mut info = MapInfo::default();
    unsafe { object_info(fd.as_raw_fd(), &mut info) }.context("read diagnostic map identity")?;
    let end = info
        .name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(info.name.len());
    anyhow::ensure!(
        &info.name[..end] == name.as_bytes(),
        "pin {name} refers to a differently named map"
    );
    check_map_layout(name, info.layout, kind, 4, size as u32)?;
    anyhow::ensure!(
        info.layout[4] as usize == entries,
        "unexpected entry count for {name}: {}",
        info.layout[4]
    );
    Ok((fd, info.layout[1]))
}

struct Target {
    filter: OwnedFd,
    samples: OwnedFd,
    filter_id: u32,
    samples_id: u32,
    ifindex: u32,
    program_id: u32,
    link_id: u32,
    _program: OwnedFd,
}

impl Target {
    fn open(args: &Args) -> anyhow::Result<Self> {
        let name = std::ffi::CString::new(args.interface.as_str())?;
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        anyhow::ensure!(ifindex != 0, "interface not found: {}", args.interface);
        let (filter, filter_id) = open_map(&args.pin_root, FILTER_MAP, 2, size_of::<Filter>(), 1)?;
        let (samples, samples_id) = open_map(
            &args.pin_root,
            SAMPLE_MAP,
            6,
            size_of::<Sample>(),
            Reason::ALL.len(),
        )?;
        let mut owner = None;
        for (program_id, link_id) in chain(ifindex)? {
            let fd = bpf(BPF_PROG_GET_FD_BY_ID, &mut [program_id, 0, 0])
                .with_context(|| format!("open attached program {program_id}"))?;
            let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
            let mut ids = [0u32; 128];
            let mut info = ProgramInfo {
                map_count: ids.len() as u32,
                map_ids: ids.as_mut_ptr() as u64,
                ..Default::default()
            };
            unsafe { object_info(fd.as_raw_fd(), &mut info) }
                .context("read attached program maps")?;
            anyhow::ensure!(
                info.map_count as usize <= ids.len(),
                "program {program_id} exceeds 128 diagnostic map IDs"
            );
            let ids = &ids[..info.map_count as usize];
            if ids.contains(&filter_id) && ids.contains(&samples_id) {
                anyhow::ensure!(
                    info.kind == 3 && info.id == program_id && link_id != 0,
                    "diagnostic maps do not belong to a TCX classifier link"
                );
                anyhow::ensure!(
                    owner.is_none(),
                    "multiple TCX programs use these diagnostic maps"
                );
                owner = Some((program_id, link_id, fd));
            }
        }
        let (program_id, link_id, program) = owner.context("diagnostic pins are not used together by this interface's TCX egress; use a matching diagnostic build")?;
        let target = Self {
            filter,
            samples,
            filter_id,
            samples_id,
            ifindex,
            program_id,
            link_id,
            _program: program,
        };
        target.check_attachment()?;
        Ok(target)
    }

    fn check_attachment(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            chain(self.ifindex)?.contains(&(self.program_id, self.link_id)),
            "diagnostic TCX attachment changed; capture is not valid, retry with the current engine"
        );
        Ok(())
    }
}

fn set_filter(fd: RawFd, value: Filter) -> io::Result<()> {
    let key = 0u32;
    let mut attr = BpfAttr {
        map_fd: fd as u32,
        key: &key as *const u32 as u64,
        value_or_next: &value as *const Filter as u64,
        ..Default::default()
    };
    bpf(BPF_MAP_UPDATE_ELEM, &mut attr).map(|_| ())
}

struct Capture<'a> {
    fd: &'a OwnedFd,
    armed: bool,
}

impl Capture<'_> {
    fn stop(&mut self) -> io::Result<()> {
        set_filter(self.fd.as_raw_fd(), Filter::default())?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for Capture<'_> {
    fn drop(&mut self) {
        if self.armed
            && let Err(error) = self.stop()
        {
            let _ = writeln!(
                io::stderr(),
                "WAN diagnostic cleanup failed: {error}; sampling may remain enabled; run honk-tool bpf wan-diag --interface DEV --disable with the original --pin-root"
            );
        }
    }
}

fn sample_json(reason: Reason, cpu_slot: usize, sample: Sample) -> Value {
    let tuple = (sample.tuple_valid != 0).then(|| {
        json!({
            "source": ip_of(&In6Addr { u6_addr8: sample.source }).to_string(),
            "source_port": sample.source_port,
            "destination": ip_of(&In6Addr { u6_addr8: sample.destination }).to_string(),
            "destination_port": sample.destination_port,
            "l4proto": sample.l4proto,
        })
    });
    json!({
        "reason_index": reason as u32, "reason": reason.label(), "cpu_slot": cpu_slot,
        "packets": sample.packets, "timestamp_ns": sample.timestamp_ns,
        "socket_cookie": sample.socket_cookie, "ifindex": sample.ifindex,
        "ingress_ifindex": sample.ingress_ifindex, "mark": sample.mark,
        "protocol": sample.protocol, "length": sample.length,
        "parse_result": sample.parse_result, "link_h_len": sample.link_h_len,
        "first_byte": sample.first_byte, "tuple": tuple,
    })
}

fn snapshot(fd: RawFd, buffer: &mut [u8]) -> anyhow::Result<Vec<Value>> {
    let mut rows = Vec::new();
    for reason in Reason::ALL {
        anyhow::ensure!(
            map_lookup(fd, &(reason as u32).to_ne_bytes(), buffer)?,
            "missing diagnostic reason slot"
        );
        for (cpu_slot, bytes) in buffer
            .as_chunks::<{ size_of::<Sample>() }>()
            .0
            .iter()
            .enumerate()
        {
            let sample = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<Sample>()) };
            if sample.packets != 0 {
                rows.push(sample_json(reason, cpu_slot, sample));
            }
        }
    }
    Ok(rows)
}

fn print_json(value: &Value) -> anyhow::Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    let target = Target::open(&args)?;
    if args.disable {
        set_filter(target.filter.as_raw_fd(), Filter::default())
            .context("disable WAN diagnostics; sampling may remain enabled")?;
        return print_json(&json!({"disabled": true, "filter_map_id": target.filter_id}));
    }
    let port = args.source_port.context("source port is required")?;
    let mut buffer = vec![
        0u8;
        percpu_buffer_len(
            possible_cpus(Path::new("/sys/devices/system/cpu"))?,
            size_of::<Sample>()
        )?
    ];
    let existing: Filter = read_value(target.filter.as_raw_fd(), &0u32.to_ne_bytes())?
        .context("missing diagnostic filter")?;
    anyhow::ensure!(
        existing.ifindex == 0 && existing.source_port == 0,
        "WAN diagnostics already enabled; do not overlap collectors, or use --disable to recover"
    );
    let before = snapshot(target.samples.as_raw_fd(), &mut buffer)?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let mut capture = Capture {
        fd: &target.filter,
        armed: false,
    };
    target.check_attachment()?;
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.seconds);
    set_filter(
        target.filter.as_raw_fd(),
        Filter {
            ifindex: target.ifindex,
            source_port: u32::from(port),
        },
    )?;
    capture.armed = true;
    let stopped = async {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => "timeout",
            _ = interrupt.recv() => "SIGINT",
            _ = terminate.recv() => "SIGTERM",
            _ = hangup.recv() => "SIGHUP",
        }
    };
    tokio::pin!(stopped);
    let message = format!(
        "WAN diagnostic sampling ready: interface={} ifindex={} source_port={} seconds={}\n",
        args.interface, target.ifindex, port, args.seconds
    );
    let mut stderr = tokio::io::stderr();
    let outcome: io::Result<&str> = tokio::select! {
        reason = &mut stopped => Ok(reason),
        ready = async {
            stderr.write_all(message.as_bytes()).await?;
            stderr.flush().await
        } => match ready {
            Ok(()) => Ok(stopped.await),
            Err(error) => Err(error),
        },
    };
    capture.stop().with_context(|| format!("disable WAN diagnostics failed (capture result: {outcome:?}); sampling may remain enabled; run honk-tool bpf wan-diag --interface {} --disable --pin-root {}", args.interface, args.pin_root.display()))?;
    let elapsed_ms = started.elapsed().as_millis();
    let end_reason = outcome.context("write diagnostic readiness")?;
    target.check_attachment()?;
    let after = snapshot(target.samples.as_raw_fd(), &mut buffer)?;
    print_json(&json!({
        "interface": args.interface, "ifindex": target.ifindex, "source_port": port,
        "program_id": target.program_id, "link_id": target.link_id,
        "filter_map_id": target.filter_id, "sample_map_id": target.samples_id,
        "requested_seconds": args.seconds, "elapsed_ms": elapsed_ms, "end_reason": end_reason,
        "coherent_snapshot": false,
        "notes": [
            "Counters are cumulative packets; each reason/cpu_slot retains only its latest sample.",
            "cpu_slot is the position in the possible-CPU buffer, not necessarily the OS CPU ID.",
            "Reasons 0..2 are interface-wide, not source-port-attributed; tuple=null means invalid.",
            "Match the complete tuple to the actual probe; cookies and dispatch do not prove interception.",
            "Disabling is not a grace barrier; a final admitted writer may race this non-atomic snapshot.",
            "Freeze engine configuration and run only one collector; filter admission is not an atomic claim."
        ],
        "before": before, "after": after,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_tuple_never_exports_stale_parser_addresses() {
        let mut sample = Sample {
            source: std::net::Ipv4Addr::new(192, 0, 2, 1)
                .to_ipv6_mapped()
                .octets(),
            destination: "2001:db8::2".parse::<Ipv6Addr>().unwrap().octets(),
            source_port: 41500,
            destination_port: 443,
            l4proto: 6,
            parse_result: -14,
            first_byte: -1,
            ..Default::default()
        };
        let failed = sample_json(Reason::ParsePass, 3, sample);
        assert!(failed["tuple"].is_null());
        assert_eq!(failed["parse_result"], -14);
        assert_eq!(failed["first_byte"], -1);
        sample.tuple_valid = 1;
        let valid = sample_json(Reason::ForwardedPass, 3, sample);
        assert_eq!(valid["tuple"]["source"], "192.0.2.1");
        assert_eq!(valid["tuple"]["destination"], "2001:db8::2");
        assert_eq!(valid["tuple"]["source_port"], 41500);
        assert_eq!(valid["tuple"]["destination_port"], 443);
    }
}
