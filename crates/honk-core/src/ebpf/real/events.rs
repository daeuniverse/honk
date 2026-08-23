use super::*;
use aya::maps::{HashMap as AyaHashMap, Map as AyaMap, MapData as AyaMapData};
use honk_ebpf_common::{
    event::{DaeEvent, DaeEventType},
    redirect_need::PIDName,
};
use std::path::Path;

type PnameMap = AyaHashMap<AyaMapData, u64, PIDName>;

pub fn open_pname_map(path: &Path) -> anyhow::Result<PnameMap> {
    let data = AyaMapData::from_pin(path)
        .map_err(|error| anyhow::anyhow!("open pname map '{}': {error}", path.display()))?;
    AyaHashMap::try_from(
        AyaMap::from_map_data(data)
            .map_err(|error| anyhow::anyhow!("open pname map '{}': {error}", path.display()))?,
    )
    .map_err(|error| anyhow::anyhow!("open pname map '{}': {error}", path.display()))
}

fn process_name_from_cmdline(command: &[u8]) -> Option<[u8; honk_ebpf_common::TASK_COMM_LEN]> {
    let argv0 = command.split(|byte| *byte == 0).next()?;
    let name = argv0.rsplit(|byte| *byte == b'/').next()?;
    if name.is_empty() {
        return None;
    }
    let mut pname = [0; honk_ebpf_common::TASK_COMM_LEN];
    let len = name.len().min(pname.len().saturating_sub(1));
    pname[..len].copy_from_slice(&name[..len]);
    Some(pname)
}

fn read_process_name(pid: u32) -> Option<[u8; honk_ebpf_common::TASK_COMM_LEN]> {
    let command = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    process_name_from_cmdline(&command)
}

fn resolve_process_name(map: &mut PnameMap, event: &DaeEvent) {
    let cookie = (event.sip[0] as u64) | ((event.sip[1] as u64) << 32);
    let mut entry = match map.get(&cookie, 0) {
        Ok(entry) => entry,
        Err(_) => return,
    };
    if entry.pid != event.pid || entry.pname.iter().any(|byte| *byte != 0) {
        return;
    }
    let Some(pname) = read_process_name(event.pid).or_else(|| {
        let pname = event.pname;
        pname.iter().any(|byte| *byte != 0).then_some(pname)
    }) else {
        return;
    };
    entry.pname = pname;
    if let Err(error) = map.insert(cookie, entry, 0) {
        debug!(target: "honk-ebpf", cookie, error = %error, "could not publish process name");
    }
}

/// Format a `DaeEvent` IP field — four u32 chunks of a 16-byte address in
/// network order, IPv4-mapped for v4 flows — as an `IpAddr` for logging.
pub fn event_ip(chunks: &[u32; 4]) -> std::net::IpAddr {
    let mut bytes = [0u8; 16];
    for (i, chunk) in chunks.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&chunk.to_ne_bytes());
    }
    let v6 = std::net::Ipv6Addr::from(bytes);
    match v6.to_ipv4_mapped() {
        Some(v4) => std::net::IpAddr::V4(v4),
        None => std::net::IpAddr::V6(v6),
    }
}

/// Maximum eBPF datapath events logged per second; excess events within the
/// window are counted and reported in aggregate when the window rolls over,
/// so a conntrack overflow burst cannot storm the log.
pub const EVENT_LOG_MAX_PER_SEC: u32 = 32;

/// Drain `EVENT_RINGBUF` into rate-limited structured logs and pname updates.
pub async fn consume_dae_events(
    mut async_fd: tokio::io::unix::AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
    mut pname_map: Option<PnameMap>,
) {
    let mut window = std::time::Instant::now();
    let mut emitted: u32 = 0;
    let mut suppressed: u64 = 0;
    loop {
        let mut guard = match async_fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                debug!("DaeEvent ringbuf AsyncFd wait failed: {}", e);
                break;
            }
        };
        {
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                let bytes: &[u8] = &item;
                if bytes.len() < core::mem::size_of::<DaeEvent>() {
                    continue;
                }
                let ev: DaeEvent =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DaeEvent) };
                if ev.type_ == DaeEventType::PnameResolve as u32 {
                    if let Some(map) = pname_map.as_mut() {
                        resolve_process_name(map, &ev);
                    }
                    continue;
                }
                if window.elapsed() >= std::time::Duration::from_secs(1) {
                    if suppressed > 0 {
                        warn!(
                            "eBPF datapath events suppressed: {} in the last second",
                            suppressed
                        );
                    }
                    window = std::time::Instant::now();
                    emitted = 0;
                    suppressed = 0;
                }
                if emitted >= EVENT_LOG_MAX_PER_SEC {
                    suppressed += 1;
                    continue;
                }
                emitted += 1;
                let pname_end = ev
                    .pname
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(ev.pname.len());
                let pname = String::from_utf8_lossy(&ev.pname[..pname_end]);
                let sip = event_ip(&ev.sip);
                let dip = event_ip(&ev.dip);
                let is_overflow = ev.type_ == DaeEventType::UdpConnOverflow as u32
                    || ev.type_ == DaeEventType::TcpConnOverflow as u32;
                let is_token_exhaustion =
                    ev.type_ == DaeEventType::UdpDecisionTokenExhausted as u32;
                let kind = match ev.type_ {
                    t if t == DaeEventType::UdpConnOverflow as u32 => "udp_conn_overflow",
                    t if t == DaeEventType::TcpConnOverflow as u32 => "tcp_conn_overflow",
                    t if t == DaeEventType::Blocked as u32 => "blocked",
                    t if t == DaeEventType::UdpDecisionTokenExhausted as u32 => {
                        "udp_decision_token_exhausted"
                    }
                    _ => "unknown",
                };
                if is_overflow {
                    warn!(target: "honk-ebpf", event = kind, pid = ev.pid, pname = %pname, l4proto = ev.l4proto, %sip, sport = ev.sport, %dip, dport = ev.dport, outbound = ev.outbound, "eBPF conntrack overflow");
                } else if is_token_exhaustion {
                    warn!(target: "honk-ebpf", event = kind, "UDP decision token allocator exhausted");
                } else {
                    info!(target: "honk-ebpf", event = kind, pid = ev.pid, pname = %pname, l4proto = ev.l4proto, %sip, sport = ev.sport, %dip, dport = ev.dport, outbound = ev.outbound, "eBPF datapath event");
                }
            }
        }
        guard.clear_ready();
    }
}

#[cfg(test)]
mod tests {
    use super::process_name_from_cmdline;

    #[test]
    fn process_name_uses_argv0_basename() {
        let name = process_name_from_cmdline(b"/usr/bin/python3\0worker\0").unwrap();
        assert_eq!(&name[..8], b"python3\0");
        assert!(name[8..].iter().all(|byte| *byte == 0));

        let name = process_name_from_cmdline(b"/tmp/abcdefghijklmnop\0").unwrap();
        assert_eq!(&name[..15], b"abcdefghijklmno");
        assert_eq!(name[15], 0);
    }
}
