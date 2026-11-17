//! Single-flight ownership of a captured original and its private TAP receive.

use super::super::fold_capture_result;
use crate::ebpf::native::{
    CapturedCell, CapturedObservation, NativeBasis, NativeClaimIdentity, NativePublication,
    OriginalExtent, PreparedOriginal,
};
use anyhow::{Context as _, ensure};
use honk_ebpf_common::xdp::{
    NATIVE_OP_ADMITTED as ADMITTED, NATIVE_OP_ADMITTING as ADMITTING, NATIVE_OP_ENTERED as ENTERED,
    NATIVE_OP_ENTERING as ENTERING, NATIVE_OP_GATE_REFUSED as GATE_REFUSED,
    NATIVE_OP_PREPARED as PREPARED, NATIVE_OP_REDIRECT_REQUESTED as REDIRECT_REQUESTED,
    NATIVE_OP_REDIRECTING as REDIRECTING, NativeImport,
};
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::MAX_SEGMENTS;
use honk_xsk::{CapturedProgramConfig, CapturedPrograms, CapturedTarget, Port, RetainedRxHandle};
use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

const IOV_MAX: usize = MAX_SEGMENTS + 3;
const TAP_MAX_MTU: u32 = 65535 - 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Completion {
    Transferred,
    Refused,
    Ambiguous,
}

pub(crate) struct OriginalProof {
    identity: NativeClaimIdentity,
    handle: RetainedRxHandle,
    producer: NativeImport,
    operation: u64,
    attachment: u64,
    entry: u64,
    completion: Completion,
}

impl OriginalProof {
    pub(crate) fn identity(&self) -> NativeClaimIdentity {
        self.identity
    }
    pub(crate) fn handle(&self) -> RetainedRxHandle {
        self.handle
    }
    pub(crate) fn producer(&self) -> NativeImport {
        self.producer
    }
    pub(crate) fn op_incarnation(&self) -> u64 {
        self.operation
    }
    pub(crate) fn return_attachment(&self) -> u64 {
        self.attachment
    }
    pub(crate) fn entry_seq(&self) -> u64 {
        self.entry
    }
    pub(crate) fn is_transferred(&self) -> bool {
        self.completion == Completion::Transferred
    }
    pub(crate) fn is_refused(&self) -> bool {
        self.completion == Completion::Refused
    }
}

pub(crate) enum OriginalOutcome {
    Transferred(OriginalProof),
    RefusedBeforeTransfer(OriginalProof),
    Ambiguous(OriginalProof),
}

struct Flight {
    prepared: PreparedOriginal,
    identity: NativeClaimIdentity,
    handle: RetainedRxHandle,
    producer: NativeImport,
    synchronous: bool,
    write_result: io::Result<usize>,
    reported: Option<Completion>,
    entry: u64,
    #[cfg(test)]
    entry_observed: bool,
    #[cfg(test)]
    grace_started: bool,
    #[cfg(test)]
    grace_completed: bool,
}

impl Flight {
    fn proof(&self, completion: Completion) -> OriginalProof {
        OriginalProof {
            identity: self.identity,
            handle: self.handle,
            producer: self.producer,
            operation: self.prepared.op_incarnation(),
            attachment: self.prepared.return_attachment(),
            entry: self.entry,
            completion,
        }
    }

    fn matches(&self, proof: &OriginalProof) -> bool {
        self.reported == Some(proof.completion)
            && proof.completion != Completion::Ambiguous
            && proof.identity == self.identity
            && proof.handle == self.handle
            && same_operation(
                (
                    self.prepared.return_attachment(),
                    self.prepared.op_incarnation(),
                    self.entry,
                ),
                (proof.attachment, proof.operation, proof.entry),
            )
            && proof.producer == self.producer
    }
}

fn same_operation(expected: (u64, u64, u64), actual: (u64, u64, u64)) -> bool {
    expected.0 != 0 && expected.1 != 0 && expected == actual
}

fn begin_allowed(sealed: bool, failed: bool, flight: bool) -> io::Result<()> {
    if sealed || failed {
        return Err(io::ErrorKind::BrokenPipe.into());
    }
    if flight {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(())
}

fn close_allowed(flight: bool, failed: bool) -> bool {
    !flight && !failed
}

fn retain_unjoined<T>(owner: Option<T>, joined: bool) {
    if !joined {
        std::mem::forget(owner);
    }
}

fn completion_after_join(
    observation: &CapturedObservation,
    synchronous: bool,
    sealed: bool,
    fresh_grace: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<Completion> {
    if observation.phase == ENTERED && observation.receipt == 1 && observation.entry_seq != 0 {
        fresh_grace()?;
        return Ok(Completion::Transferred);
    }
    if synchronous
        && sealed
        && observation.phase == GATE_REFUSED
        && observation.receipt == 0
        && observation.entry_seq == 0
    {
        fresh_grace()?;
        return Ok(Completion::Refused);
    }
    Ok(Completion::Ambiguous)
}

fn checked_extent(segments: &[&[u8]], extent: OriginalExtent) -> io::Result<usize> {
    let length = segments
        .iter()
        .try_fold(0usize, |n, bytes| n.checked_add(bytes.len()))
        .ok_or_else(|| invalid("captured original extent overflow"))?;
    if segments.is_empty()
        || segments.len() > MAX_SEGMENTS
        || segments.iter().any(|b| b.is_empty())
        || length != extent.frame_length as usize
        || length < 14
        || extent.l3_offset < 14
        || extent.l3_length == 0
        || extent
            .l3_offset
            .checked_add(extent.l3_length)
            .is_none_or(|end| end > extent.frame_length)
        || extent.vlan_count > 2
        || extent.inline_vlan_count > extent.vlan_count
        || extent.l3_offset != 14 + 4 * u32::from(extent.inline_vlan_count)
        || extent.dscp > 63
    {
        return Err(invalid(
            "captured original is not the complete retained frame",
        ));
    }
    for index in 0..usize::from(extent.vlan_count) {
        if !matches!(extent.vlan_proto[index], 0x8100 | 0x88a8) {
            return Err(invalid("captured original VLAN protocol"));
        }
    }
    Ok(length)
}

fn write_original(fd: &OwnedFd, segments: &[&[u8]], extent: OriginalExtent) -> io::Result<usize> {
    let length = checked_extent(segments, extent)?;
    let hidden = usize::from(extent.vlan_count - extent.inline_vlan_count);
    let mut tags = [0u8; 8];
    for index in 0..hidden {
        tags[index * 4..index * 4 + 2].copy_from_slice(&extent.vlan_proto[index].to_be_bytes());
        tags[index * 4 + 2..index * 4 + 4].copy_from_slice(&extent.vlan_tci[index].to_be_bytes());
    }
    let mut vectors = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; IOV_MAX];
    let mut count = 0;
    let mut push = |bytes: &[u8]| -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if count == IOV_MAX {
            return Err(invalid("captured writev exceeds stack vector bound"));
        }
        vectors[count] = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        count += 1;
        Ok(())
    };
    let mut position = 0;
    let mut inserted = hidden == 0;
    for bytes in segments {
        if !inserted && position + bytes.len() >= 12 {
            let split = 12 - position;
            push(&bytes[..split])?;
            push(&tags[..hidden * 4])?;
            push(&bytes[split..])?;
            inserted = true;
        } else {
            push(bytes)?;
        }
        position += bytes.len();
    }
    if !inserted || length.checked_add(hidden * 4).is_none() {
        return Err(invalid("captured VLAN insertion extent"));
    }
    // Ordinary writev has no MSG_MORE/control-message path. Never retry this syscall:
    // a negative result can follow final XDP admission.
    let written = unsafe { libc::writev(fd.as_raw_fd(), vectors.as_ptr(), count as libc::c_int) };
    if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(written as usize)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn boottime_ns() -> io::Result<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|value| {
            u64::try_from(time.tv_nsec)
                .ok()
                .and_then(|ns| value.checked_add(ns))
        })
        .ok_or_else(|| invalid("captured BOOTTIME overflow"))
}

struct Tap {
    fd: OwnedFd,
    name: String,
    ifindex: u32,
    namespace: u64,
    admin_mtu: u32,
}

fn ifreq(name: &str) -> io::Result<libc::ifreq> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.bytes().any(|b| b == 0 || b == b'/')
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (out, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *out = byte as _;
    }
    Ok(request)
}

fn tap_flags(flags: u32) -> bool {
    flags & !(libc::IFF_TUN_EXCL as u32 | 0x8000) == (libc::IFF_TAP | libc::IFF_NO_PI) as u32
}

fn synchronous_readbacks(
    flags: u32,
    queues: usize,
    rps: &str,
    flows: u32,
    batched: u32,
    timestamping: u32,
    phc: i32,
) -> bool {
    tap_flags(flags)
        && queues == 1
        && rps.trim().split(',').all(|part| {
            !part.is_empty() && part.len() <= 8 && part.bytes().all(|byte| byte == b'0')
        })
        && flows == 0
        && batched == 0
        && timestamping & 4 == 0
        && phc < 0
}

fn check_tap_geometry(body: &[u8], ifindex: u32, name: &str, admin_mtu: u32) -> io::Result<u32> {
    if body.len() < 16
        || u16::from_ne_bytes(body[2..4].try_into().unwrap()) != libc::ARPHRD_ETHER
        || u32::from_ne_bytes(body[4..8].try_into().unwrap()) != ifindex
    {
        return Err(invalid("private TAP link identity/type readback"));
    }
    let mut fields = [None; 4];
    crate::netlink::fib::attributes(&body[16..], |kind, value| {
        let index = match kind {
            1 => 0,  // IFLA_ADDRESS
            3 => 1,  // IFLA_IFNAME
            4 => 2,  // IFLA_MTU
            51 => 3, // IFLA_MAX_MTU
            _ => return Ok(()),
        };
        if fields[index].replace(value).is_some() {
            return Err(invalid("private TAP duplicate geometry attribute"));
        }
        Ok(())
    })?;
    let mtu = fields[2]
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .map(u32::from_ne_bytes)
        .ok_or_else(|| invalid("private TAP missing/malformed MTU"))?;
    if fields[0].is_none_or(|address| address.len() != 6)
        || fields[1].and_then(|value| value.strip_suffix(&[0])) != Some(name.as_bytes())
        || mtu != admin_mtu
        || fields[3] != Some(TAP_MAX_MTU.to_ne_bytes().as_slice())
    {
        return Err(invalid("private TAP Ethernet geometry readback"));
    }
    Ok(mtu)
}

impl Tap {
    fn open(attachment: u64, namespace: u64, admin_mtu: u32) -> io::Result<Self> {
        let name = format!("nr{attachment:x}");
        let mut request = ifreq(&name)?;
        let fd: OwnedFd = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open("/dev/net/tun")?
            .into();
        request.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as _;
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let ifindex = match nix::net::if_::if_nametoindex(name.as_str()) {
            Ok(ifindex) => ifindex,
            Err(error) => {
                std::mem::forget(fd);
                return Err(error.into());
            }
        };
        let tap = Self {
            fd,
            name,
            ifindex,
            namespace,
            admin_mtu,
        };
        // The file remains in the failed owner even if a later readback fails.
        Ok(tap)
    }

    fn configure(&self) -> anyhow::Result<u32> {
        for (key, value) in [("disable_ipv6", "1"), ("accept_ra", "0"), ("autoconf", "0")] {
            let path = format!("/proc/sys/net/ipv6/conf/{}/{key}", self.name);
            std::fs::write(&path, value)?;
            ensure!(
                std::fs::read_to_string(&path)?.trim() == value,
                "private TAP IPv6 readback"
            );
        }
        let mut nl = crate::netlink::NlSock::new()?;
        nl.set_link_mtu(self.ifindex, self.admin_mtu)
            .map_err(|error| anyhow::anyhow!("private TAP MTU: {error:?}"))?;
        // No vnet header exists; clearing offloads also prevents inherited tun offload state.
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TUNSETOFFLOAD, 0 as libc::c_ulong) } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        let mut coalesce = [0u32; 23];
        coalesce[0] = 0x0f;
        ethtool(&socket, &self.name, &mut coalesce)?;
        let queues = PathBuf::from("/sys/class/net")
            .join(&self.name)
            .join("queues/rx-0");
        for entry in ["rps_cpus", "rps_flow_cnt"] {
            std::fs::write(queues.join(entry), "0")?;
        }
        let mut request = [0u8; 16];
        request[4..8].copy_from_slice(&self.ifindex.to_ne_bytes());
        let mut mtu = None;
        netlink_exchange(&mut nl, 18, 16, 5, &request, |body| {
            if mtu.is_some() {
                return Err(invalid("private TAP duplicate link readback"));
            }
            mtu = Some(check_tap_geometry(
                body,
                self.ifindex,
                &self.name,
                self.admin_mtu,
            )?);
            Ok(())
        })?;
        mtu.context("private TAP geometry readback missing")
    }

    fn check_private_receive(&self) -> io::Result<()> {
        let status = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
        let descriptor = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFD) };
        if status < 0 || descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        if status & libc::O_NONBLOCK == 0 || descriptor & libc::FD_CLOEXEC == 0 {
            return Err(invalid("private TAP descriptor flags changed"));
        }
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TUNGETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let actual_name = request
            .ifr_name
            .iter()
            .map(|&byte| byte as u8)
            .take_while(|&byte| byte != 0);
        if !actual_name.eq(self.name.bytes()) {
            return Err(invalid("private TAP name changed"));
        }
        let flags = u32::from(unsafe { request.ifr_ifru.ifru_flags } as u16);
        let raw = unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TUNGETDEVNETNS) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let namespace = File::from(unsafe { OwnedFd::from_raw_fd(raw) }).metadata()?;
        let current = std::fs::metadata("/proc/thread-self/ns/net")?;
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        if (namespace.dev(), namespace.ino()) != (current.dev(), current.ino())
            || crate::netlink::fib::namespace_cookie(socket.as_raw_fd())? != self.namespace
            || nix::net::if_::if_nametoindex(self.name.as_str())? != self.ifindex
        {
            return Err(invalid("private TAP namespace/device changed"));
        }
        let root = PathBuf::from("/sys/class/net").join(&self.name);
        let number = |path: &Path| -> io::Result<u32> {
            std::fs::read_to_string(path)?
                .trim()
                .parse()
                .map_err(|_| invalid("private TAP numeric readback"))
        };
        if number(&root.join("mtu"))? != self.admin_mtu {
            return Err(invalid("private TAP MTU changed"));
        }
        let mut queues = 0;
        for entry in std::fs::read_dir(root.join("queues"))? {
            let entry = entry?;
            if entry.file_name().as_encoded_bytes().starts_with(b"rx-") {
                if entry.file_name() != "rx-0" || !entry.file_type()?.is_dir() {
                    return Err(invalid("private TAP has foreign RX queue"));
                }
                queues += 1;
            }
        }
        let rps = std::fs::read_to_string(root.join("queues/rx-0/rps_cpus"))?;
        let flows = number(&root.join("queues/rx-0/rps_flow_cnt"))?;
        // ethtool_coalesce is 23 u32; rx_max_coalesced_frames is member 2.
        let mut coalesce = [0u32; 23];
        coalesce[0] = 0x0e;
        ethtool(&socket, &self.name, &mut coalesce)?;
        let mut timestamps = [0u32; 11];
        timestamps[0] = 0x41;
        ethtool(&socket, &self.name, &mut timestamps)?;
        // Fresh, exclusive stock TAP has no PHY; absent ndo_hwtstamp_get/set
        // makes Linux 7.2.5 tsconfig refuse provider selection. TS_INFO checks consistency;
        // get_rps_cpu exits when both queue tables are absent.
        if !synchronous_readbacks(
            flags,
            queues,
            &rps,
            flows,
            coalesce[2],
            timestamps[1],
            timestamps[2] as i32,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "private TAP synchronous receive prerequisites",
            ));
        }
        for (key, value) in [("disable_ipv6", "1"), ("accept_ra", "0"), ("autoconf", "0")] {
            if std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{}/{key}", self.name))?
                .trim()
                != value
            {
                return Err(invalid("private TAP IPv6 prerequisite changed"));
            }
        }
        let packet = std::fs::read_to_string("/proc/thread-self/net/packet")?;
        for line in packet.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            let bound: u32 = fields
                .get(4)
                .ok_or_else(|| invalid("packet socket inventory"))?
                .parse()
                .map_err(|_| invalid("packet socket interface"))?;
            if bound == 0 || bound == self.ifindex {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "packet socket may inject into private TAP",
                ));
            }
        }
        check_no_l3(self.ifindex)?;
        Ok(())
    }
}

fn ethtool(socket: &socket2::Socket, name: &str, value: &mut [u32]) -> io::Result<()> {
    let mut request = ifreq(name)?;
    request.ifr_ifru.ifru_data = value.as_mut_ptr().cast();
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCETHTOOL, &mut request) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn check_no_l3(ifindex: u32) -> io::Result<()> {
    let mut route = crate::netlink::NlSock::new()?;
    for family in [libc::AF_INET, libc::AF_INET6] {
        let mut address = [0u8; 8];
        address[0] = family as u8;
        netlink_exchange(&mut route, 22, 20, 0x301, &address, |body| {
            if body.len() < 8 {
                return Err(invalid("short address readback"));
            }
            if u32::from_ne_bytes(body[4..8].try_into().unwrap()) == ifindex {
                return Err(invalid("private TAP acquired an address"));
            }
            Ok(())
        })?;
        let mut request = [0u8; 12];
        request[0] = family as u8;
        netlink_exchange(&mut route, 26, 24, 0x301, &request, |body| {
            if body.len() < 12 {
                return Err(invalid("short route readback"));
            }
            crate::netlink::fib::attributes(&body[12..], |kind, bytes| {
                if matches!(kind, 3 | 4) && bytes == ifindex.to_ne_bytes() {
                    return Err(invalid("private TAP acquired a route"));
                }
                if kind == 9 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "multipath route cannot exclude private TAP",
                    ));
                }
                Ok(())
            })
        })?;
    }
    Ok(())
}

fn netlink_exchange(
    socket: &mut crate::netlink::NlSock,
    kind: u16,
    response: u16,
    flags: u16,
    body: &[u8],
    mut visit: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    use crate::netlink::fib::{completion_error, header};
    socket.seq = socket
        .seq
        .checked_add(1)
        .ok_or_else(|| invalid("private netlink sequence exhausted"))?;
    let sequence = socket.seq;
    let mut request = Vec::with_capacity(16 + body.len());
    request.extend_from_slice(&((body.len() + 16) as u32).to_ne_bytes());
    request.extend_from_slice(&kind.to_ne_bytes());
    request.extend_from_slice(&flags.to_ne_bytes());
    request.extend_from_slice(&sequence.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.extend_from_slice(body);
    let mutation = kind >> 8 == 10 && matches!(kind & 255, 0 | 2 | 3 | 6);
    if mutation {
        let mut batch = Vec::with_capacity(request.len() + 40);
        batch.extend_from_slice(&20u32.to_ne_bytes());
        batch.extend_from_slice(&0x10u16.to_ne_bytes());
        batch.extend_from_slice(&1u16.to_ne_bytes());
        batch.extend_from_slice(&sequence.to_ne_bytes());
        batch.extend_from_slice(&0u32.to_ne_bytes());
        batch.extend_from_slice(&[0, 0, 0, 10]);
        batch.extend_from_slice(&request);
        batch.extend_from_slice(&20u32.to_ne_bytes());
        batch.extend_from_slice(&0x11u16.to_ne_bytes());
        batch.extend_from_slice(&1u16.to_ne_bytes());
        batch.extend_from_slice(&sequence.to_ne_bytes());
        batch.extend_from_slice(&0u32.to_ne_bytes());
        batch.extend_from_slice(&[0, 0, 0, 10]);
        socket.send_datagram(&batch)?;
    } else {
        socket.send_datagram(&request)?;
    }
    let mut receive = Vec::new();
    let mut messages = 0;
    loop {
        let length = socket.recv_one(&mut receive)?;
        let mut bytes = &receive[..length];
        let mut done = false;
        while !bytes.is_empty() {
            messages += 1;
            let (len, reply, reply_flags, seq) = header(bytes)?;
            if seq != sequence || reply_flags & 0x10 != 0 || done || messages > 65536 {
                return Err(invalid("private netlink interrupted/mismatched reply"));
            }
            if matches!(reply, 2 | 3) {
                let errno = completion_error(
                    reply,
                    reply_flags,
                    &bytes[16..len],
                    &request,
                    flags & 0x300 == 0x300,
                )?;
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(errno));
                }
                done = true;
            } else if reply == response {
                visit(&bytes[16..len])?;
            } else {
                return Err(invalid("private netlink unexpected reply"));
            }
            bytes = &bytes[len.next_multiple_of(4)..];
        }
        if done {
            return Ok(());
        }
    }
}

fn attribute(out: &mut Vec<u8>, kind: u16, bytes: &[u8]) {
    out.extend_from_slice(&((bytes.len() + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(bytes);
    out.resize(out.len().next_multiple_of(4), 0);
}

fn text_attribute(out: &mut Vec<u8>, kind: u16, text: &str) {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    attribute(out, kind, &bytes);
}

fn check_hook(bytes: &[u8], device: &str) -> io::Result<()> {
    let mut seen = 0u8;
    crate::netlink::fib::attributes(bytes, |kind, value| {
        if !(1..=4).contains(&kind) || seen & (1 << kind) != 0 {
            return Err(invalid(
                "private nft hook has unknown or duplicate attribute",
            ));
        }
        seen |= 1 << kind;
        match kind {
            1 if value == 0u32.to_be_bytes() => {}
            2 if value == i32::MIN.to_be_bytes() => {}
            3 if value.strip_suffix(&[0]) == Some(device.as_bytes()) => {}
            4 => {
                let mut devices = 0;
                crate::netlink::fib::attributes(value, |kind, name| {
                    devices += 1;
                    if kind != 1
                        || devices != 1
                        || name.strip_suffix(&[0]) != Some(device.as_bytes())
                    {
                        return Err(invalid("private nft hook device list changed"));
                    }
                    Ok(())
                })?;
                if devices != 1 {
                    return Err(invalid("private nft hook device list empty"));
                }
            }
            _ => return Err(invalid("private nft hook changed")),
        }
        Ok(())
    })?;
    if seen & 6 != 6 || seen & 24 == 0 {
        return Err(invalid("private nft hook incomplete"));
    }
    Ok(())
}

fn sole_attribute(bytes: &[u8], expected: u16) -> io::Result<&[u8]> {
    let mut value = None;
    crate::netlink::fib::attributes(bytes, |kind, bytes| {
        if kind != expected || value.replace(bytes).is_some() {
            return Err(invalid("private nft expression has extra attribute"));
        }
        Ok(())
    })?;
    value.ok_or_else(|| invalid("private nft expression attribute absent"))
}

fn paired_attributes(bytes: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let mut first = None;
    let mut second = None;
    crate::netlink::fib::attributes(bytes, |kind, bytes| {
        let slot = match kind {
            1 => &mut first,
            2 => &mut second,
            _ => return Err(invalid("private nft expression unknown attribute")),
        };
        if slot.replace(bytes).is_some() {
            return Err(invalid("private nft expression duplicate attribute"));
        }
        Ok(())
    })?;
    Ok((
        first.ok_or_else(|| invalid("private nft expression first attribute absent"))?,
        second.ok_or_else(|| invalid("private nft expression second attribute absent"))?,
    ))
}

fn check_drop_expression(bytes: &[u8]) -> io::Result<()> {
    // Kernel dumps omit nesting flags; the shared parser masks both NLA flags.
    let expression = sole_attribute(bytes, 1)?;
    let (name, immediate) = paired_attributes(expression)?;
    if name != b"immediate\0" {
        return Err(invalid("private terminal expression changed"));
    }
    let (register, data) = paired_attributes(immediate)?;
    let verdict = sole_attribute(data, 2)?;
    let code = sole_attribute(verdict, 1)?;
    if register != 0u32.to_be_bytes() || code != 0u32.to_be_bytes() {
        return Err(invalid("private terminal verdict is not NF_DROP"));
    }
    Ok(())
}

struct Containment {
    socket: crate::netlink::NlSock,
    table: String,
    device: String,
    table_handle: u64,
    chain_handle: u64,
    rule_handle: u64,
}

impl Containment {
    fn new(attachment: u64, device: &str) -> io::Result<Self> {
        Ok(Self {
            socket: crate::netlink::NlSock::from_protocol(libc::NETLINK_NETFILTER)?,
            table: format!("honk_native_return_{attachment}"),
            device: device.into(),
            table_handle: 0,
            chain_handle: 0,
            rule_handle: 0,
        })
    }

    fn body(&self) -> Vec<u8> {
        let mut body = vec![5, 0, 0, 10];
        text_attribute(&mut body, 1, &self.table);
        body
    }

    fn drop_expression() -> Vec<u8> {
        let mut verdict = Vec::new();
        attribute(&mut verdict, 1, &0u32.to_be_bytes());
        let mut data = Vec::new();
        attribute(&mut data, 2 | 0x8000, &verdict);
        let mut immediate = Vec::new();
        attribute(&mut immediate, 1, &0u32.to_be_bytes());
        attribute(&mut immediate, 2 | 0x8000, &data);
        let mut expression = Vec::new();
        text_attribute(&mut expression, 1, "immediate");
        attribute(&mut expression, 2 | 0x8000, &immediate);
        let mut list = Vec::new();
        attribute(&mut list, 1 | 0x8000, &expression);
        list
    }

    fn install(&mut self) -> io::Result<()> {
        // CREATE|EXCL refuses stale tables instead of adopting somebody else's guard.
        let body = self.body();
        netlink_exchange(&mut self.socket, 0x0a00, 0x0a00, 0x605, &body, |_| Ok(()))?;
        let mut body = self.body();
        text_attribute(&mut body, 3, "ingress");
        let mut hook = Vec::new();
        attribute(&mut hook, 1, &0u32.to_be_bytes());
        attribute(&mut hook, 2, &i32::MIN.to_be_bytes());
        text_attribute(&mut hook, 3, &self.device);
        attribute(&mut body, 4 | 0x8000, &hook);
        attribute(&mut body, 5, &0u32.to_be_bytes());
        text_attribute(&mut body, 7, "filter");
        netlink_exchange(&mut self.socket, 0x0a03, 0x0a03, 0x605, &body, |_| Ok(()))?;
        let mut rule = self.body();
        text_attribute(&mut rule, 2, "ingress");
        attribute(&mut rule, 4 | 0x8000, &Self::drop_expression());
        netlink_exchange(&mut self.socket, 0x0a06, 0x0a06, 0x605, &rule, |_| Ok(()))?;
        self.readback(false)
    }

    fn readback(&mut self, compare: bool) -> io::Result<()> {
        let mut body = self.body();
        let mut table_handle = 0;
        netlink_exchange(&mut self.socket, 0x0a01, 0x0a00, 0x005, &body, |payload| {
            if payload.len() < 4 {
                return Err(invalid("short private nft table"));
            }
            crate::netlink::fib::attributes(&payload[4..], |kind, bytes| {
                if kind == 4 {
                    table_handle = u64::from_be_bytes(
                        bytes.try_into().map_err(|_| invalid("nft table handle"))?,
                    );
                }
                Ok(())
            })
        })?;
        text_attribute(&mut body, 3, "ingress");
        let mut chain_handle = 0;
        let mut policy = false;
        let mut hook_seen = false;
        let device = self.device.clone();
        netlink_exchange(&mut self.socket, 0x0a04, 0x0a03, 0x005, &body, |payload| {
            if payload.len() < 4 {
                return Err(invalid("short private nft chain"));
            }
            crate::netlink::fib::attributes(&payload[4..], |kind, bytes| {
                match kind {
                    2 => {
                        chain_handle = u64::from_be_bytes(
                            bytes.try_into().map_err(|_| invalid("nft chain handle"))?,
                        )
                    }
                    5 => policy = bytes == 0u32.to_be_bytes(),
                    4 => {
                        if hook_seen {
                            return Err(invalid("private nft hook duplicated"));
                        }
                        check_hook(bytes, &device)?;
                        hook_seen = true;
                    }
                    _ => {}
                }
                Ok(())
            })
        })?;
        let mut rule = self.body();
        text_attribute(&mut rule, 2, "ingress");
        let mut rules = 0;
        let mut rule_handle = 0;
        netlink_exchange(&mut self.socket, 0x0a07, 0x0a06, 0x301, &rule, |payload| {
            if payload.len() < 4 {
                return Err(invalid("short private nft rule"));
            }
            rules += 1;
            let mut drop_seen = false;
            crate::netlink::fib::attributes(&payload[4..], |kind, bytes| {
                match kind {
                    3 => {
                        rule_handle = u64::from_be_bytes(
                            bytes.try_into().map_err(|_| invalid("nft rule handle"))?,
                        )
                    }
                    4 => {
                        if drop_seen {
                            return Err(invalid("private nft expressions duplicated"));
                        }
                        check_drop_expression(bytes)?;
                        drop_seen = true;
                    }
                    _ => {}
                }
                Ok(())
            })?;
            if !drop_seen {
                return Err(invalid("private terminal rule changed"));
            }
            Ok(())
        })?;
        if rules != 1 || rule_handle == 0 || compare && rule_handle != self.rule_handle {
            return Err(invalid("private terminal rule replaced"));
        }
        self.rule_handle = rule_handle;
        if table_handle == 0
            || chain_handle == 0
            || !policy
            || !hook_seen
            || compare && (self.table_handle != table_handle || self.chain_handle != chain_handle)
        {
            return Err(invalid("private terminal DROP containment changed"));
        }
        self.table_handle = table_handle;
        self.chain_handle = chain_handle;
        Ok(())
    }

    fn remove(&mut self) -> io::Result<()> {
        self.readback(true)?;
        let mut body = vec![5, 0, 0, 10];
        attribute(&mut body, 4, &self.table_handle.to_be_bytes());
        netlink_exchange(&mut self.socket, 0x0a02, 0x0a02, 0x005, &body, |_| Ok(()))
    }
}

struct Receipt {
    path: PathBuf,
    file: File,
    value: serde_json::Value,
    sha256: [u8; 32],
}

fn write_receipt(file: &mut File, value: &serde_json::Value) -> anyhow::Result<[u8; 32]> {
    struct HashedFile<'a> {
        file: &'a mut File,
        hash: Sha256,
    }
    impl io::Write for HashedFile<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let written = self.file.write(bytes)?;
            self.hash.update(&bytes[..written]);
            Ok(written)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }
    let mut writer = HashedFile {
        file,
        hash: Sha256::new(),
    };
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.file.sync_all()?;
    Ok(writer.hash.finalize().into())
}

impl Receipt {
    fn create(
        data_dir: &Path,
        namespace: u64,
        attachment: u64,
        root: &Path,
    ) -> anyhow::Result<Self> {
        let directory = crate::state::state_directory(data_dir, true, crate::state::private)?;
        let name = format!("native-return-{namespace}.json");
        let file: File = nix::fcntl::openat(
            &directory,
            name.as_str(),
            nix::fcntl::OFlag::O_WRONLY
                | nix::fcntl::OFlag::O_CREAT
                | nix::fcntl::OFlag::O_EXCL
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )?
        .into();
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let starttime: u64 = stat
            .rsplit_once(')')
            .context("process stat")?
            .1
            .split_whitespace()
            .nth(19)
            .context("process starttime")?
            .parse()?;
        let mut receipt = Self {
            path: data_dir.join(crate::state::STATE_DIR).join(name),
            file,
            value: serde_json::json!({"format":2,"source_sha":env!("HONK_SOURCE_SHA"),
                "pid":std::process::id(),"starttime":starttime,"namespace":namespace,
                "return_attachment":attachment,"pin_root":root,"operation_bytes":264,
                "phase":"preparing","resources":[]}),
            sha256: [0; 32],
        };
        receipt.write()?;
        directory.sync_all()?;
        Ok(receipt)
    }

    fn write(&mut self) -> anyhow::Result<()> {
        self.sha256 = write_receipt(&mut self.file, &self.value)?;
        Ok(())
    }

    fn persist(&mut self) -> anyhow::Result<()> {
        let expected = self.file.metadata()?;
        let actual = std::fs::symlink_metadata(&self.path)?;
        ensure!(
            actual.is_file()
                && !actual.file_type().is_symlink()
                && (actual.dev(), actual.ino()) == (expected.dev(), expected.ino()),
            "Native return receipt replaced"
        );
        let temporary = self.path.with_extension("json.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        let sha256 = write_receipt(&mut file, &self.value)?;
        let actual = std::fs::symlink_metadata(&self.path)?;
        ensure!(
            (actual.dev(), actual.ino()) == (expected.dev(), expected.ino()),
            "Native return receipt changed during persist"
        );
        std::fs::rename(temporary, &self.path)?;
        self.file = file;
        File::open(self.path.parent().context("receipt parent")?)?.sync_all()?;
        self.sha256 = sha256;
        Ok(())
    }

    fn intent(&mut self, role: &str, identity: serde_json::Value) -> anyhow::Result<usize> {
        let entries = self.value["resources"]
            .as_array_mut()
            .context("Native receipt resources")?;
        let index = entries.len();
        entries.push(serde_json::json!({"role":role,"state":"intent","identity":identity}));
        self.persist()?;
        Ok(index)
    }

    fn ack(&mut self, index: usize, observed: serde_json::Value) -> anyhow::Result<()> {
        let entry = self.value["resources"]
            .get_mut(index)
            .context("Native receipt intent")?;
        ensure!(
            entry["state"] == "intent",
            "Native return acknowledgment without intent"
        );
        entry["state"] = serde_json::json!("installed");
        entry["observed"] = observed;
        self.persist()
    }

    fn phase(&mut self, phase: &str) -> anyhow::Result<()> {
        self.value["phase"] = serde_json::json!(phase);
        self.persist()
    }

    fn archive_joined(&mut self, inventory: serde_json::Value) -> anyhow::Result<JoinedReceipt> {
        self.value["terminal_inventory"] = inventory;
        self.phase("joined")?;
        let namespace = self.value["namespace"]
            .as_u64()
            .context("receipt namespace")?;
        let attachment = self.value["return_attachment"]
            .as_u64()
            .context("receipt attachment")?;
        let parent = File::open(self.path.parent().context("receipt parent")?)?;
        let old = std::ffi::CString::new(
            self.path
                .file_name()
                .context("receipt name")?
                .as_encoded_bytes(),
        )?;
        let name = format!("native-return-{namespace}-{attachment}.joined.json");
        let new = std::ffi::CString::new(name.as_bytes())?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                old.as_ptr(),
                parent.as_raw_fd(),
                new.as_ptr(),
                1u32,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        self.path.set_file_name(name);
        if let Err(error) = self.file.sync_all().and_then(|()| parent.sync_all()) {
            tracing::error!(path = %self.path.display(), %error,
                "Native joined receipt durability failed; evidence remains unacknowledged");
            return Err(error.into());
        }
        Ok(JoinedReceipt {
            return_attachment: attachment,
            path: self.path.clone(),
            sha256: self.sha256,
        })
    }
}

struct Resources {
    publication: Arc<NativePublication>,
    cell: CapturedCell,
    tap: Option<Tap>,
    programs: Option<Arc<CapturedPrograms>>,
    containment: Option<Containment>,
    receipt: Receipt,
    flight: Option<Flight>,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    sealed: bool,
    failed: bool,
    charge: MemoryReservation,
    _cold: MemoryReservation,
    #[cfg(test)]
    fault: Option<CapturedFault>,
}

pub(crate) struct JoinedReceipt {
    pub(crate) return_attachment: u64,
    pub(crate) path: PathBuf,
    pub(crate) sha256: [u8; 32],
}

pub(crate) struct CapturedReturn {
    resources: Option<Resources>,
    joined: bool,
    joined_receipt: Option<JoinedReceipt>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum CapturedFault {
    MissingEntry,
    NegativeAfterAdmission,
}

impl Drop for CapturedReturn {
    fn drop(&mut self) {
        // Cancellation keeps the exact operation, installed prefix and its charge.
        retain_unjoined(self.resources.take(), self.joined);
    }
}

fn reserve_private(budget: &Arc<MemoryBudget>, bytes: usize) -> io::Result<MemoryReservation> {
    budget.reserve(bytes).ok_or_else(|| {
        // This snapshot explains a refusal; only the atomic reservation admits memory.
        let used = budget.used();
        let limit = budget.limit();
        io::Error::new(io::ErrorKind::OutOfMemory, format!(
            "captured private memory budget: requested={bytes} used={used} limit={limit} available={}",
            limit.saturating_sub(used)
        ))
    })
}

fn reserve_then_create<L, T>(
    budget: &Arc<MemoryBudget>,
    bytes: usize,
    admit: impl FnOnce() -> io::Result<L>,
    create: impl FnOnce(MemoryReservation, L) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let charge = reserve_private(budget, bytes)?;
    let layout = admit()?;
    create(charge, layout)
}

impl CapturedReturn {
    pub(crate) fn joined_receipt(&self) -> Option<&JoinedReceipt> {
        self.joined_receipt.as_ref()
    }

    pub(crate) fn prepare(
        publication: Arc<NativePublication>,
        targets: &[CapturedTarget],
        budget: Arc<MemoryBudget>,
        pin_root: &Path,
        data_dir: &Path,
    ) -> anyhow::Result<Self> {
        use crate::ebpf::native::NativeReason;
        ensure!(
            !targets.is_empty() && targets.len() <= 4096,
            "captured return target bound"
        );
        // Covers bounded netlink/receipt scratch before querying the cold inventory.
        let cold_bytes = targets
            .len()
            .checked_mul(8192)
            .and_then(|bytes| bytes.checked_add(4 * 1024 * 1024))
            .context("captured receipt inventory overflow")?;
        let cold = reserve_private(&budget, cold_bytes)?;
        let mut nl = crate::netlink::NlSock::new()?;
        let namespace = crate::netlink::fib::namespace_cookie(nl.fd.as_raw_fd())?;
        let links = nl.dump_links()?;
        let mut max_physical_mtu = 0;
        for (index, target) in targets.iter().enumerate() {
            let authority = target.target.capture().authority;
            ensure!(
                authority.is_valid()
                    && authority.namespace_cookie == namespace
                    && target.logical_ifindex != 0
                    && target.realm_index != u32::MAX
                    && !targets[..index]
                        .iter()
                        .any(|other| other.realm_index == target.realm_index),
                "captured target authority/realm"
            );
            let link = links
                .iter()
                .find(|link| link.ifindex.get() == authority.ifindex)
                .context("captured physical ingress missing")?;
            let info = honk_xsk::device::DeviceInfo::discover(&link.name)?;
            ensure!(
                info.ifindex == authority.ifindex,
                "captured target identity changed"
            );
            ensure!((68..=65535).contains(&info.mtu), "captured target MTU");
            max_physical_mtu = max_physical_mtu.max(info.mtu);
        }
        let private_admin_mtu = max_physical_mtu.min(TAP_MAX_MTU);
        let max_original_frame_bytes = max_physical_mtu
            .checked_add(22)
            .context("captured original frame bound overflow")?;
        let bytes =
            honk_xsk::NativeTarget::captured_preparation_bytes(max_physical_mtu, targets.len())?;
        reserve_then_create(
            &budget,
            bytes,
            || targets[0].target.admit_captured_layout(),
            |charge, layout| {
                let writer = publication.write(NativeReason::Startup)?;
                let cell = publication.create_captured_cell(&writer)?;
                let attachment = cell.return_attachment().as_u64();
                let root = pin_root.join(format!("native-return-{attachment}"));
                let receipt = Receipt::create(data_dir, namespace, attachment, &root)?;
                let mut owner = Self {
                    resources: Some(Resources {
                        publication: publication.clone(),
                        cell,
                        tap: None,
                        programs: None,
                        containment: None,
                        receipt,
                        flight: None,
                        timer: None,
                        sealed: false,
                        failed: false,
                        charge,
                        _cold: cold,
                        #[cfg(test)]
                        fault: None,
                    }),
                    joined: false,
                    joined_receipt: None,
                };
                let resources = owner.resources.as_mut().expect("new captured owner");
                let tap_intent = resources.receipt.intent(
                    "private-tap",
                    serde_json::json!({
            "name":format!("nr{attachment:x}"),"namespace":namespace,"mtu":private_admin_mtu,
            "max_physical_ip_mtu":max_physical_mtu,"max_original_frame_bytes":max_original_frame_bytes,
            "flags":libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL,"persistent":false}),
                )?;
                resources.tap = Some(Tap::open(attachment, namespace, private_admin_mtu)?);
                let tap = resources.tap.as_ref().expect("owned TAP");
                let stat = nix::sys::stat::fstat(&tap.fd)?;
                resources.receipt.ack(
                    tap_intent,
                    serde_json::json!({"ifindex":tap.ifindex,"fd":tap.fd.as_raw_fd(),
            "fd_device":stat.st_dev,"fd_inode":stat.st_ino}),
                )?;
                let configuration = resources.receipt.intent("private-tap-configuration", serde_json::json!({
            "ifindex":tap.ifindex,"mtu":private_admin_mtu,"offloads":0,"rx_batched":0,"rps_cpus":"0","rps_flow_cnt":0,
            "disable_ipv6":1,"accept_ra":0,"autoconf":0}))?;
                let actual_mtu = tap.configure()?;
                tap.check_private_receive()?;
                resources.receipt.ack(
                    configuration,
                    serde_json::json!({"readback":"matched",
                        "mtu":actual_mtu,"max_mtu":TAP_MAX_MTU,"arphrd":libc::ARPHRD_ETHER}),
                )?;
                let guard_intent = resources.receipt.intent("terminal-netdev-drop", serde_json::json!({
            "table":format!("honk_native_return_{attachment}"),"chain":"ingress","ifindex":tap.ifindex}))?;
                resources.containment = Some(Containment::new(attachment, &tap.name)?);
                let containment = resources.containment.as_mut().expect("owned containment");
                containment.install()?;
                resources.receipt.ack(guard_intent, serde_json::json!({"table_handle":containment.table_handle,
            "chain_handle":containment.chain_handle,"rule_handle":containment.rule_handle,"policy":"drop"}))?;
                let inventory_intent = resources.receipt.intent("private-installation", serde_json::json!({
            "root":root,"operation_map_bytes":264,"static_programs":6,
            "targets":targets.iter().map(|target| {
                let authority = target.target.capture().authority;
                serde_json::json!({"realm_index":target.realm_index,"logical_ifindex":target.logical_ifindex,
                    "ifindex":authority.ifindex,"namespace_cookie":authority.namespace_cookie,
                    "attachment_generation":authority.attachment_generation,"scope":authority.scope,
                    "config_generation":authority.config_generation})
            }).collect::<Vec<_>>(),
            "pins":["operation-map","realm-dispatch-map","tap-xdp-guard","tap-xdp-dispatch",
                "tap-tcx-redirect-prog","tap-tcx-guard-prog","target-entry-prog","target-entry-link"],
            "target_pins":["native-return-restorer-prog","native-return-restorer-link"]}))?;
                let config = CapturedProgramConfig {
                    pin_root,
                    root: resources.cell.root_fd(),
                    operation: resources.cell.operation_fd(),
                    return_attachment: attachment,
                    tap_ifindex: tap.ifindex,
                    targets,
                };
                resources.programs = Some(Arc::new(
                    targets[0].target.load_captured_programs(&config, layout)?,
                ));
                let programs = resources
                    .programs
                    .as_ref()
                    .expect("owned captured programs");
                ensure!(
                    programs.memory_bytes()? <= resources.charge.bytes(),
                    "captured installed inventory exceeds pre-reserve"
                );
                // Parsing returned only a scalar layout before loading began. Keep preparation
                // funded until the installed inventory has secured its overlapping reservation.
                let installed = reserve_private(&budget, programs.memory_bytes()?)?;
                resources.charge = installed;
                programs.check()?;
                tap.check_private_receive()?;
                publication.register_captured(&resources.cell, programs.clone(), &writer)?;
                let inventory = programs.inventory();
                ensure!(
                    !inventory.is_empty()
                        && inventory.iter().all(|item| item.id != 0
                            && item.state == honk_xsk::CapturedResourceState::Installed
                            && item.pin_path.starts_with(pin_root)),
                    "captured concrete program receipt"
                );
                for target in targets {
                    let ifindex = target.target.capture().authority.ifindex;
                    for role in ["native-return-restorer-prog", "native-return-restorer-link"] {
                        let expected = pin_root.join(format!("xdp-{ifindex}")).join(role);
                        ensure!(
                            inventory.iter().any(|item| item.role == role
                                && item.ifindex == ifindex
                                && item.pin_path == expected),
                            "captured target gate directory differs from registered custody"
                        );
                    }
                }
                resources.receipt.ack(inventory_intent, serde_json::json!({
            "root_map_id":programs.root_map_id(),"operation_map_id":programs.operation_map_id(),
            "objects":inventory.iter().map(|item| serde_json::json!({"role":item.role,"pin_path":item.pin_path,
                "kind":item.kind,"id":item.id,"ifindex":item.ifindex,"state":"Installed"})).collect::<Vec<_>>()}))?;
                nl.set_link_up(tap.ifindex, true)?;
                tap.check_private_receive()?;
                containment.readback(true)?;
                resources.receipt.phase("ready")?;
                writer.commit();
                Ok(owner)
            },
        )
    }

    pub(crate) fn is_idle(&self) -> bool {
        self.resources
            .as_ref()
            .is_none_or(|resources| resources.flight.is_none())
    }

    pub(crate) fn begin_original<L>(
        &mut self,
        port: &Port<L>,
        handle: RetainedRxHandle,
        basis: &NativeBasis,
    ) -> io::Result<()> {
        port.with_retained_rx(handle, |segments, _| {
            self.begin_segments(handle, basis, segments)
        })?
    }

    /// The remote worker retains the original Port slot until it acknowledges the returned proof.
    pub(crate) fn begin_copied_original(
        &mut self,
        handle: RetainedRxHandle,
        basis: &NativeBasis,
        packet: &[u8],
    ) -> io::Result<()> {
        self.begin_segments(handle, basis, &[packet])
    }

    fn begin_segments(
        &mut self,
        handle: RetainedRxHandle,
        basis: &NativeBasis,
        segments: &[&[u8]],
    ) -> io::Result<()> {
        let resources = self
            .resources
            .as_mut()
            .ok_or_else(|| invalid("captured owner already closed"))?;
        begin_allowed(
            resources.sealed,
            resources.failed,
            resources.flight.is_some(),
        )?;
        let tap = resources
            .tap
            .as_ref()
            .ok_or_else(|| invalid("captured TAP absent"))?;
        tap.check_private_receive()?;
        resources
            .containment
            .as_mut()
            .ok_or_else(|| invalid("captured containment absent"))?
            .readback(true)?;
        resources
            .programs
            .as_ref()
            .ok_or_else(|| invalid("captured programs absent"))?
            .check()?;
        let extent = basis.extent();
        checked_extent(segments, extent)?;
        let prepared = resources
            .publication
            .prepare_original(&resources.cell, basis)
            .map_err(to_io)?;
        if !resources.publication.original_epoch_is_open(&prepared)
            || boottime_ns()? >= prepared.expires_boottime_ns()
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        resources.flight = Some(Flight {
            prepared,
            identity: basis.identity(),
            handle,
            producer: basis.producer(),
            synchronous: true,
            write_result: Ok(0),
            reported: None,
            entry: 0,
            #[cfg(test)]
            entry_observed: false,
            #[cfg(test)]
            grace_started: false,
            #[cfg(test)]
            grace_completed: false,
        });
        // Install the flight before any syscall so unwind retains its exact Port owner.
        #[cfg(test)]
        if let Some(fault) = resources.fault.take() {
            let programs = resources.programs.as_ref().expect("checked programs");
            match fault {
                CapturedFault::MissingEntry => programs.remove_entry_witness_for_test()?,
                CapturedFault::NegativeAfterAdmission => {
                    // The real TAP TCX guard drops after private XDP admission;
                    // Linux may still return a full write length for that drop.
                    programs.refuse_after_admission_for_test()?;
                }
            }
        }
        let flight = resources
            .flight
            .as_mut()
            .expect("installed captured flight");
        flight.write_result = write_original(&tap.fd, segments, extent);
        Ok(())
    }

    pub(crate) fn poll_original(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<anyhow::Result<OriginalOutcome>> {
        let Some(resources) = self.resources.as_mut() else {
            return Poll::Pending;
        };
        let Some(flight) = resources.flight.as_mut() else {
            return Poll::Pending;
        };
        if flight.reported.is_some() {
            return Poll::Pending;
        }
        let observation = resources.cell.observe(&flight.prepared);
        let in_progress = match &observation {
            Ok(observed) => matches!(
                observed.phase,
                ADMITTING | ADMITTED | REDIRECTING | REDIRECT_REQUESTED | ENTERING
            ),
            Err(error) => error.kind() == io::ErrorKind::WouldBlock,
        };
        if in_progress
            && !resources.failed
            && !resources.sealed
            && boottime_ns().is_ok_and(|now| now < flight.prepared.expires_boottime_ns())
        {
            let timer = resources
                .timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(1))));
            if timer.as_mut().poll(cx).is_ready() {
                timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + Duration::from_millis(1));
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
        let completion = match observation {
            Ok(observation) if observation.phase == ENTERED => {
                flight.entry = observation.entry_seq;
                #[cfg(test)]
                {
                    flight.entry_observed = true;
                }
                if resources.failed {
                    Ok(Completion::Ambiguous)
                } else {
                    completion_after_join(&observation, flight.synchronous, false, || {
                        #[cfg(test)]
                        {
                            flight.grace_started = true;
                        }
                        let result = resources.publication.original_grace();
                        #[cfg(test)]
                        {
                            flight.grace_completed = result.is_ok();
                        }
                        result
                    })
                }
            }
            Ok(observation) if matches!(observation.phase, PREPARED | GATE_REFUSED) => {
                resources.sealed = true;
                let mut failure = None;
                let sealed = match resources.programs.as_ref() {
                    Some(programs) => {
                        fold_capture_result(&mut failure, programs.seal().map_err(Into::into));
                        failure.is_none()
                    }
                    None => false,
                };
                if failure.is_some() {
                    resources.failed = true;
                    fold_capture_result(&mut failure, resources.publication.original_grace());
                    Err(failure.unwrap())
                } else if resources.failed {
                    Ok(Completion::Ambiguous)
                } else {
                    completion_after_join(&observation, flight.synchronous, sealed, || {
                        resources.publication.original_grace()
                    })
                }
            }
            _ => Ok(Completion::Ambiguous),
        };
        let completion = match completion {
            Ok(completion) => completion,
            Err(error) => {
                resources.failed = true;
                return Poll::Ready(Err(error));
            }
        };
        resources.failed |= completion == Completion::Ambiguous;
        flight.reported = Some(completion);
        tracing::debug!(operation = flight.prepared.op_incarnation(), phase_outcome = ?completion,
            write_result = ?flight.write_result, "captured original observation");
        let proof = flight.proof(completion);
        Poll::Ready(Ok(match completion {
            Completion::Transferred => OriginalOutcome::Transferred(proof),
            Completion::Refused => OriginalOutcome::RefusedBeforeTransfer(proof),
            Completion::Ambiguous => OriginalOutcome::Ambiguous(proof),
        }))
    }

    pub(crate) fn settle_original(&mut self, proof: OriginalProof) -> io::Result<()> {
        let resources = self
            .resources
            .as_mut()
            .ok_or_else(|| invalid("captured owner closed"))?;
        if !resources
            .flight
            .as_ref()
            .is_some_and(|flight| flight.matches(&proof))
        {
            resources.failed = true;
            return Err(invalid(
                "captured completion is stale, duplicate or ambiguous",
            ));
        }
        resources.flight = None;
        resources.timer = None;
        Ok(())
    }

    pub(crate) fn seal(&mut self) -> anyhow::Result<()> {
        use crate::ebpf::native::NativeReason;
        let Some(resources) = self.resources.as_mut() else {
            return Ok(());
        };
        let mut failure = resources
            .failed
            .then(|| anyhow::anyhow!("captured private owner remains failed-retained"));
        if !self.joined {
            resources.sealed = true;
            fold_capture_result(&mut failure, resources.receipt.phase("closing"));
            fold_capture_result(
                &mut failure,
                resources.publication.quiesce(NativeReason::Shutdown),
            );
            if let Some(programs) = &resources.programs {
                fold_capture_result(&mut failure, programs.seal().map_err(Into::into));
            }
        }
        fold_capture_result(&mut failure, resources.publication.original_grace());
        resources.failed |= failure.is_some();
        failure.map_or(Ok(()), Err)
    }

    pub(crate) fn finish_close(&mut self) -> anyhow::Result<bool> {
        if self.joined {
            return Ok(true);
        }
        let result = (|| {
            self.seal()?;
            let Some(resources) = self.resources.as_mut() else {
                return Ok(true);
            };
            if !close_allowed(resources.flight.is_some(), resources.failed) {
                resources.receipt.phase("failed-retained")?;
                return Ok(false);
            }
            let closed = (|| -> anyhow::Result<bool> {
                let programs = resources
                    .programs
                    .as_ref()
                    .context("captured programs absent")?;
                if !programs.finish_close()? {
                    return Ok(false);
                }
                resources.receipt.phase("private-hooks-joined")?;
                if let Some(containment) = &mut resources.containment {
                    containment.remove()?;
                }
                let tap = resources.tap.as_ref().context("captured TAP absent")?;
                tap.check_private_receive()?;
                let fd = tap.fd.as_raw_fd();
                let tap = &mut resources.tap;
                programs.close_tap(fd, || {
                    let tap = tap
                        .take()
                        .ok_or_else(|| invalid("captured TAP already consumed"))?;
                    let fd = tap.fd.into_raw_fd();
                    if unsafe { libc::close(fd) } < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                })?;
                Ok(true)
            })();
            let (closed, mut failure) = match closed {
                Ok(closed) => (closed, None),
                Err(error) => (false, Some(error)),
            };
            fold_capture_result(&mut failure, resources.publication.original_grace());
            if let Some(error) = failure {
                return Err(error);
            }
            if !closed {
                resources.receipt.phase("failed-retained")?;
                return Ok(false);
            }
            let programs = resources
                .programs
                .as_ref()
                .context("captured terminal inventory absent")?;
            let inventory = programs.inventory();
            ensure!(!inventory.is_empty(), "empty captured terminal inventory");
            for item in &inventory {
                ensure!(
                    item.state != honk_xsk::CapturedResourceState::Installed,
                    "captured resource remains installed after joined close"
                );
                if item.state == honk_xsk::CapturedResourceState::Unpinned {
                    match std::fs::symlink_metadata(&item.pin_path) {
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        _ => anyhow::bail!("captured pin still present after joined close"),
                    }
                }
            }
            for target in programs.targets() {
                let ifindex = target.target.capture().authority.ifindex;
                for (role, state) in [
                    (
                        "native-return-restorer-link",
                        honk_xsk::CapturedResourceState::Detached,
                    ),
                    (
                        "native-return-restorer-link",
                        honk_xsk::CapturedResourceState::Unpinned,
                    ),
                    (
                        "native-return-restorer-prog",
                        honk_xsk::CapturedResourceState::Unpinned,
                    ),
                ] {
                    ensure!(
                        inventory.iter().any(|item| item.role == role
                            && item.ifindex == ifindex
                            && item.state == state),
                        "captured restorer terminal transition absent"
                    );
                }
            }
            let joined_receipt = resources.receipt.archive_joined(serde_json::json!(inventory.iter().map(|item| serde_json::json!({
            "role":item.role,"pin_path":item.pin_path,"kind":item.kind,"id":item.id,"ifindex":item.ifindex,
            "state":match item.state { honk_xsk::CapturedResourceState::Installed => "Installed",
                honk_xsk::CapturedResourceState::Detached => "Detached", honk_xsk::CapturedResourceState::Unpinned => "Unpinned" }
        })).collect::<Vec<_>>()))?;
            self.joined_receipt = Some(joined_receipt);
            self.joined = true;
            Ok(true)
        })();
        if !matches!(&result, Ok(true))
            && let Some(resources) = self.resources.as_mut()
        {
            resources.failed = true;
        }
        result
    }
}

fn to_io(error: anyhow::Error) -> io::Error {
    match error.downcast::<io::Error>() {
        Ok(error) => error,
        Err(error) => io::Error::other(error),
    }
}

#[cfg(test)]
fn flight_observation(
    observation: io::Result<CapturedObservation>,
) -> io::Result<serde_json::Value> {
    match observation {
        Ok(observation) => Ok(serde_json::json!({
            "status": "observed",
            "phase": observation.phase,
            "receipt": observation.receipt,
            "entry_seq": observation.entry_seq,
        })),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            Ok(serde_json::json!({"status": "publication-in-progress"}))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
impl CapturedReturn {
    pub(crate) fn set_fault(&mut self, fault: CapturedFault) -> io::Result<()> {
        let resources = self
            .resources
            .as_mut()
            .ok_or_else(|| invalid("captured owner closed"))?;
        begin_allowed(
            resources.sealed,
            resources.failed,
            resources.flight.is_some(),
        )?;
        resources.fault = Some(fault);
        Ok(())
    }

    pub(crate) fn is_missing_entry_readback_error(error: &anyhow::Error) -> bool {
        let top: &(dyn std::error::Error + 'static) = error.as_ref();
        top.downcast_ref::<io::Error>()
            .is_some_and(CapturedPrograms::is_missing_entry_readback_error_for_test)
    }

    pub(crate) fn check_missing_entry_containment(&self) -> io::Result<()> {
        self.resources
            .as_ref()
            .and_then(|resources| resources.programs.as_ref())
            .ok_or_else(|| invalid("captured programs absent"))?
            .check_missing_entry_containment_for_test()
    }

    pub(crate) fn check_private_receive(&self) -> io::Result<()> {
        self.resources
            .as_ref()
            .and_then(|resources| resources.tap.as_ref())
            .ok_or_else(|| invalid("captured TAP absent"))?
            .check_private_receive()
    }

    pub(crate) fn tap_ifindex(&self) -> u32 {
        self.resources
            .as_ref()
            .and_then(|resources| resources.tap.as_ref())
            .expect("live private TAP")
            .ifindex
    }

    pub(crate) fn tap_name(&self) -> &str {
        &self
            .resources
            .as_ref()
            .and_then(|resources| resources.tap.as_ref())
            .expect("live private TAP")
            .name
    }

    pub(crate) fn flight_receipt(&self) -> anyhow::Result<serde_json::Value> {
        let resources = self.resources.as_ref().context("captured owner closed")?;
        let flight = resources
            .flight
            .as_ref()
            .context("captured flight absent")?;
        let observation = flight_observation(resources.cell.observe(&flight.prepared))?;
        let handle = flight.handle.receipt_identity();
        let key = flight.identity.key;
        let write = match &flight.write_result {
            Ok(length) => serde_json::json!({"length":length}),
            Err(error) => {
                serde_json::json!({"errno":error.raw_os_error(),"error":error.to_string()})
            }
        };
        Ok(
            serde_json::json!({"return_attachment":flight.prepared.return_attachment(),
            "op_incarnation":flight.prepared.op_incarnation(),"slot":0,
            "prepared_expires_boottime_ns":flight.prepared.expires_boottime_ns(),
            "port_identity":{"port":handle.port,"port_generation":handle.port_generation,
                "slot":handle.slot,"slot_generation":handle.slot_generation},
            "claim":{"epoch":flight.identity.epoch,"incarnation":flight.identity.incarnation,"scope":flight.identity.scope},
            "key":{"src_ip":key.src_ip,"dst_ip":key.dst_ip,"src_port":key.src_port,"dst_port":key.dst_port,
                "l4proto":key.l4proto,"ip_version":key.ip_version,"domain":key.domain,"direction":key.direction,
                "namespace_cookie":key.namespace_cookie,"zone":key.zone,"zone_state":key.zone_state,"reserved":key.reserved},
            "producer":{"epoch":flight.producer.epoch,"incarnation":flight.producer.incarnation,
                "expires_boottime_ns":flight.producer.expires_boottime_ns,"flags":flight.producer.flags},
            "write_result":write,"observation":observation,
            "entry_observed":flight.entry_observed,"fresh_grace_started":flight.grace_started,
            "fresh_grace_completed":flight.grace_completed,"failed_retained":resources.failed,
            "owner_receipt":resources.receipt.value}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn missing_entry_control_rejects_untyped_or_contextual_errors() {
        for error in [
            anyhow::anyhow!("missing entry"),
            io::Error::new(io::ErrorKind::InvalidData, "missing entry").into(),
            io::Error::from_raw_os_error(libc::ENOENT).into(),
            anyhow::Error::from(io::Error::other("missing entry")).context("additional failure"),
        ] {
            assert!(!CapturedReturn::is_missing_entry_readback_error(&error));
        }
    }

    #[test]
    fn captured_private_tap_requires_exact_cold_ethernet_geometry() {
        let readback = |mtu: u32, maximum: Option<&[u8]>, address: &[u8]| {
            let mut body = vec![0; 16];
            body[2..4].copy_from_slice(&libc::ARPHRD_ETHER.to_ne_bytes());
            body[4..8].copy_from_slice(&7u32.to_ne_bytes());
            attribute(&mut body, 1, address);
            text_attribute(&mut body, 3, "nr7");
            attribute(&mut body, 4, &mtu.to_ne_bytes());
            if let Some(maximum) = maximum {
                attribute(&mut body, 50, &68u32.to_ne_bytes());
                attribute(&mut body, 51, maximum);
            }
            body
        };
        let address = [2, 0, 0, 0, 0, 7];
        let maximum = 65521u32.to_ne_bytes();
        let wrong_maximum = 65535u32.to_ne_bytes();
        let body = readback(65521, Some(&maximum), &address);
        assert_eq!(check_tap_geometry(&body, 7, "nr7", 65521).unwrap(), 65521);
        assert!(check_tap_geometry(&body, 8, "nr7", 65521).is_err());
        assert!(check_tap_geometry(&body, 7, "nr8", 65521).is_err());
        assert!(check_tap_geometry(&body, 7, "nr7", 65535).is_err());
        assert!(check_tap_geometry(&body[..15], 7, "nr7", 65521).is_err());
        let mut wrong_type = body.clone();
        wrong_type[2..4].copy_from_slice(&0u16.to_ne_bytes());
        assert!(check_tap_geometry(&wrong_type, 7, "nr7", 65521).is_err());
        for maximum in [None, Some(&maximum[..3]), Some(wrong_maximum.as_slice())] {
            assert!(
                check_tap_geometry(&readback(65521, maximum, &address), 7, "nr7", 65521).is_err()
            );
        }
        assert!(
            check_tap_geometry(&readback(65520, Some(&maximum), &address), 7, "nr7", 65521)
                .is_err()
        );
        assert!(
            check_tap_geometry(
                &readback(65521, Some(&maximum), &address[..5]),
                7,
                "nr7",
                65521
            )
            .is_err()
        );
        for (kind, value) in [
            (1, address.as_slice()),
            (3, b"nr7\0".as_slice()),
            (4, maximum.as_slice()),
            (51, maximum.as_slice()),
        ] {
            let mut duplicate = body.clone();
            attribute(&mut duplicate, kind, value);
            assert!(check_tap_geometry(&duplicate, 7, "nr7", 65521).is_err());
        }
        let mut malformed = body.clone();
        malformed.pop();
        assert!(check_tap_geometry(&malformed, 7, "nr7", 65521).is_err());
        let small = readback(1500, Some(&maximum), &address);
        assert_eq!(check_tap_geometry(&small, 7, "nr7", 1500).unwrap(), 1500);
    }

    #[test]
    fn captured_containment_accepts_single_owned_hook_device_list() {
        let hook = |devices: &[&str], direct: Option<&str>| {
            let mut bytes = Vec::new();
            attribute(&mut bytes, 1, &0u32.to_be_bytes());
            attribute(&mut bytes, 2, &i32::MIN.to_be_bytes());
            let mut list = Vec::new();
            for device in devices {
                text_attribute(&mut list, 1, device);
            }
            attribute(&mut bytes, 4, &list);
            if let Some(device) = direct {
                text_attribute(&mut bytes, 3, device);
            }
            bytes
        };
        assert!(check_hook(&hook(&["nr7"], Some("nr7")), "nr7").is_ok());
        assert!(check_hook(&hook(&["nr7"], None), "nr7").is_ok());
        assert!(check_hook(&hook(&["foreign"], Some("nr7")), "nr7").is_err());
        assert!(check_hook(&hook(&["nr7"], Some("foreign")), "nr7").is_err());
        assert!(check_hook(&hook(&["nr7", "foreign"], None), "nr7").is_err());
        assert!(check_hook(&hook(&["nr7", "nr7"], None), "nr7").is_err());
        assert!(check_hook(&hook(&[], Some("nr7")), "nr7").is_err());
        let mut duplicate = hook(&["nr7"], None);
        text_attribute(&mut duplicate, 3, "nr7");
        text_attribute(&mut duplicate, 3, "nr7");
        assert!(check_hook(&duplicate, "nr7").is_err());
        let mut foreign = hook(&["nr7"], None);
        attribute(&mut foreign, 5, &[]);
        let mut prefix = Vec::new();
        text_attribute(&mut prefix, 2, "nr");
        let mut prefix_hook = Vec::new();
        attribute(&mut prefix_hook, 1, &0u32.to_be_bytes());
        attribute(&mut prefix_hook, 2, &i32::MIN.to_be_bytes());
        attribute(&mut prefix_hook, 4, &prefix);
        assert!(check_hook(&prefix_hook, "nr7").is_err());
        assert!(check_hook(&foreign, "nr7").is_err());
    }

    #[test]
    fn captured_containment_validates_dumped_drop_semantically() {
        let dump = |flags: u16, register: u32, code: u32, name: &str| {
            let mut verdict = Vec::new();
            attribute(&mut verdict, 1 | flags, &code.to_be_bytes());
            let mut data = Vec::new();
            attribute(&mut data, 2 | flags, &verdict);
            let mut immediate = Vec::new();
            attribute(&mut immediate, 1 | flags, &register.to_be_bytes());
            attribute(&mut immediate, 2 | flags, &data);
            let mut expression = Vec::new();
            text_attribute(&mut expression, 1 | flags, name);
            attribute(&mut expression, 2 | flags, &immediate);
            let mut list = Vec::new();
            attribute(&mut list, 1 | flags, &expression);
            list
        };
        let unflagged = dump(0, 0, 0, "immediate");
        assert_ne!(unflagged, Containment::drop_expression());
        for flags in [0, 0x8000, 0x4000, 0xc000] {
            assert!(check_drop_expression(&dump(flags, 0, 0, "immediate")).is_ok());
        }
        assert!(check_drop_expression(&dump(0, 0, 1, "immediate")).is_err());
        assert!(check_drop_expression(&dump(0, 1, 0, "immediate")).is_err());
        assert!(check_drop_expression(&dump(0, 0, 0, "counter")).is_err());
        let mut extra = unflagged.clone();
        extra.extend_from_slice(&unflagged);
        assert!(check_drop_expression(&extra).is_err());
        assert!(check_drop_expression(&unflagged[..unflagged.len() - 1]).is_err());
        let mut duplicate = Vec::new();
        attribute(&mut duplicate, 1, &0u32.to_be_bytes());
        attribute(&mut duplicate, 1, &0u32.to_be_bytes());
        assert!(sole_attribute(&duplicate, 1).is_err());
        attribute(&mut duplicate, 2, &0u32.to_be_bytes());
        assert!(paired_attributes(&duplicate).is_err());
    }

    fn observation(phase: u32) -> CapturedObservation {
        CapturedObservation {
            phase,
            receipt: u32::from(phase == ENTERED),
            entry_seq: u64::from(phase == ENTERED),
        }
    }

    #[test]
    fn captured_flight_observation_preserves_availability_and_fatal_errors() {
        assert_eq!(
            flight_observation(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "captured operation publication in progress",
            )))
            .unwrap(),
            serde_json::json!({"status": "publication-in-progress"})
        );
        for (kind, cause) in [
            (
                io::ErrorKind::PermissionDenied,
                "captured operation identity changed",
            ),
            (
                io::ErrorKind::Other,
                "captured operation publication in progress",
            ),
            (io::ErrorKind::InvalidData, "invalid captured operation"),
        ] {
            let error = flight_observation(Err(io::Error::new(kind, cause))).unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(error.get_ref().unwrap().to_string(), cause);
        }
        let error = io::Error::from_raw_os_error(libc::EIO);
        let kind = error.kind();
        let cause = error.to_string();
        let error = flight_observation(Err(error)).unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(error.to_string(), cause);
        for phase in [ADMITTED, ENTERED] {
            let mut actual = observation(phase);
            if phase == ENTERED {
                actual.entry_seq = 77;
            }
            let expected = serde_json::json!({
                "status": "observed",
                "phase": phase,
                "receipt": actual.receipt,
                "entry_seq": actual.entry_seq,
            });
            assert_eq!(flight_observation(Ok(actual)).unwrap(), expected);
        }
    }

    #[test]
    fn captured_operation_requires_entry_then_fresh_grace() {
        let calls = Cell::new(0);
        for phase in [
            PREPARED,
            ADMITTING,
            ADMITTED,
            REDIRECTING,
            REDIRECT_REQUESTED,
            ENTERING,
        ] {
            assert_eq!(
                completion_after_join(&observation(phase), true, false, || {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .unwrap(),
                Completion::Ambiguous
            );
            assert_eq!(calls.get(), 0);
        }
        assert_eq!(
            completion_after_join(&observation(ENTERED), true, false, || {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .unwrap(),
            Completion::Transferred
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            completion_after_join(
                &CapturedObservation {
                    phase: ENTERED,
                    receipt: 0,
                    entry_seq: 1
                },
                true,
                false,
                || panic!("unpublished receipt")
            )
            .unwrap(),
            Completion::Ambiguous
        );
        assert_eq!(
            completion_after_join(
                &CapturedObservation {
                    phase: ENTERED,
                    receipt: 1,
                    entry_seq: 0
                },
                true,
                false,
                || panic!("unpublished entry")
            )
            .unwrap(),
            Completion::Ambiguous
        );
        assert_eq!(
            completion_after_join(
                &CapturedObservation {
                    phase: ENTERED,
                    receipt: 2,
                    entry_seq: 1
                },
                true,
                false,
                || panic!("unknown receipt")
            )
            .unwrap(),
            Completion::Ambiguous
        );
    }

    #[test]
    fn captured_duplicate_write_and_late_receipt_do_not_reuse_flight() {
        assert!(begin_allowed(false, false, false).is_ok());
        assert_eq!(
            begin_allowed(false, false, true).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            begin_allowed(true, false, false).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            begin_allowed(false, true, false).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(same_operation((7, 12, 1), (7, 12, 1)));
        assert!(!same_operation((7, 14, 1), (7, 12, 1)));
        assert!(!same_operation((8, 12, 1), (7, 12, 1)));
        assert!(!same_operation((7, 12, 2), (7, 12, 1)));
        assert!(!same_operation((0, 0, 0), (0, 0, 0)));
    }

    #[test]
    fn captured_write_result_never_proves_transfer() {
        let file: OwnedFd = OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap()
            .into();
        let first = [0u8; 13];
        let rest = [1u8; 115];
        let extent = OriginalExtent {
            frame_length: 128,
            l3_offset: 14,
            l3_length: 100,
            vlan_tci: [0; 2],
            vlan_proto: [0; 2],
            vlan_count: 0,
            inline_vlan_count: 0,
            dscp: 0,
        };
        assert_eq!(
            write_original(&file, &[&first, &rest], extent).unwrap(),
            128
        );
        assert_eq!(
            completion_after_join(&observation(GATE_REFUSED), true, true, || Ok(())).unwrap(),
            Completion::Refused
        );
        let read_only: OwnedFd = File::open("/dev/null").unwrap().into();
        assert!(write_original(&read_only, &[&first, &rest], extent).is_err());
        assert_eq!(
            completion_after_join(&observation(ENTERED), true, false, || Ok(())).unwrap(),
            Completion::Transferred
        );
        assert_eq!(
            completion_after_join(&observation(REDIRECT_REQUESTED), true, true, || Ok(())).unwrap(),
            Completion::Ambiguous
        );
        let tagged = OriginalExtent {
            vlan_count: 2,
            vlan_proto: [0x88a8, 0x8100],
            vlan_tci: [7, 9],
            ..extent
        };
        assert_eq!(
            write_original(&file, &[&first, &rest], tagged).unwrap(),
            136
        );
        assert!(checked_extent(&[&first], extent).is_err());
    }

    #[test]
    fn captured_missing_entry_and_failed_grace_retain_owner() {
        for phase in [REDIRECT_REQUESTED, ENTERING] {
            assert_eq!(
                completion_after_join(&observation(phase), true, true, || panic!("no entry"))
                    .unwrap(),
                Completion::Ambiguous
            );
        }
        assert_eq!(
            completion_after_join(&observation(ENTERED), true, true, || anyhow::bail!(
                "grace failed"
            ))
            .unwrap_err()
            .to_string(),
            "grace failed"
        );
        assert_eq!(
            completion_after_join(&observation(GATE_REFUSED), true, true, || anyhow::bail!(
                "producer join failed"
            ))
            .unwrap_err()
            .to_string(),
            "producer join failed"
        );
        assert!(!close_allowed(true, false));
        assert!(!close_allowed(false, true));
    }

    #[test]
    fn captured_sync_refusal_requires_timestamp_and_rps_prerequisites() {
        let flags = (libc::IFF_TAP | libc::IFF_NO_PI) as u32;
        assert!(synchronous_readbacks(flags, 1, "00000000,0\n", 0, 0, 0, -1));
        assert!(!synchronous_readbacks(flags, 1, "1", 0, 0, 0, -1));
        assert!(!synchronous_readbacks(flags, 1, "0", 1, 0, 0, -1));
        assert!(!synchronous_readbacks(flags, 1, "0", 0, 1, 0, -1));
        assert!(!synchronous_readbacks(flags, 1, "0", 0, 0, 4, -1));
        assert!(!synchronous_readbacks(flags, 1, "0", 0, 0, 0, 0));
        assert!(!synchronous_readbacks(flags, 2, "0", 0, 0, 0, -1));
        assert!(!synchronous_readbacks(flags, 1, ",", 0, 0, 0, -1));
        for prohibited in [0x10, 0x20, 0x100, 0x200, 0x4000, 0x800] {
            assert!(!synchronous_readbacks(
                flags | prohibited,
                1,
                "0",
                0,
                0,
                0,
                -1
            ));
        }
        assert_eq!(
            completion_after_join(&observation(GATE_REFUSED), false, true, || panic!(
                "unknown synchronous receive"
            ))
            .unwrap(),
            Completion::Ambiguous
        );
        assert_eq!(
            completion_after_join(&observation(GATE_REFUSED), true, false, || panic!(
                "unsealed producer"
            ))
            .unwrap(),
            Completion::Ambiguous
        );
        assert_eq!(
            completion_after_join(&observation(GATE_REFUSED), true, true, || Ok(())).unwrap(),
            Completion::Refused
        );
    }

    #[test]
    fn captured_close_keeps_unresolved_operation_and_charge() {
        let budget = MemoryBudget::new(128);
        let charge = reserve_private(&budget, 64).unwrap();
        retain_unjoined(Some(charge), close_allowed(true, false));
        assert_eq!(budget.used(), 64);
        let joined_charge = reserve_private(&budget, 64).unwrap();
        retain_unjoined(Some(joined_charge), close_allowed(false, false));
        assert_eq!(budget.used(), 64);
        assert!(!close_allowed(false, true));
    }

    #[test]
    fn captured_private_budget_precedes_tap_creation() {
        let budget = MemoryBudget::new(64);
        let created = Cell::new(false);
        let live = reserve_private(&budget, 16).unwrap();
        let result = reserve_then_create(
            &budget,
            49,
            || -> io::Result<()> { panic!("layout admission before reservation") },
            |_, _| {
                created.set(true);
                Ok(())
            },
        );
        let error = result.unwrap_err().downcast::<io::Error>().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(!created.get());
        assert_eq!(budget.used(), 16);
        drop(live);
        assert_eq!(budget.used(), 0);
        let refused = reserve_then_create(
            &budget,
            64,
            || -> io::Result<()> {
                assert_eq!(budget.used(), 64);
                Err(io::ErrorKind::Unsupported.into())
            },
            |_, _| {
                created.set(true);
                Ok(())
            },
        );
        assert_eq!(
            refused.unwrap_err().downcast::<io::Error>().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(!created.get());
        assert_eq!(budget.used(), 0);
        let charge = reserve_then_create(
            &budget,
            64,
            || {
                assert_eq!(budget.used(), 64);
                Ok(7u32)
            },
            |charge, layout| {
                assert_eq!(layout, 7);
                assert_eq!(budget.used(), 64);
                created.set(true);
                Ok(charge)
            },
        )
        .unwrap();
        assert!(created.get());
        assert_eq!(charge.bytes(), 64);
        assert_eq!(budget.used(), 64);
    }
}
