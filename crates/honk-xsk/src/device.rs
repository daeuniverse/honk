//! Fail-closed Ethernet root discovery; upper interfaces require canonical FIB admission.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use crate::port::{BindMode, FRAME_SIZE, MAX_SEGMENTS, METADATA_SIZE, Port, PortConfig};
use honk_netstack::{MemoryBudget, MemoryReservation};

const MAX_UPPER_INTERFACES: usize = 4096;
// Attaching our guard may publish these NDO-XMIT flags; AF_XDP TX does not use them.
const NDO_XMIT_FEATURES: u64 = 4 | 64;

#[derive(Debug)]
pub struct DeviceInfo {
    pub name: String,
    pub ifindex: u32,
    /// Direct sysfs uppers, not proof that any descendant is safe to capture.
    pub upper_ifindices: Vec<u32>,
    pub queues: Vec<u32>,
    pub mtu: u32,
    pub mac: [u8; 6],
    pub xdp_features: u64,
    pub zerocopy_max_segments: u32,
    pub vlan_metadata: bool,
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

impl DeviceInfo {
    pub fn discover(name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.len() >= libc::IFNAMSIZ
            || name.contains('/')
            || name.as_bytes().contains(&0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface name",
            ));
        }
        let path = Path::new("/sys/class/net").join(name);
        let number = |file: &str| -> io::Result<u32> {
            fs::read_to_string(path.join(file))?
                .trim()
                .parse()
                .map_err(|_| unsupported(format!("invalid {file}")))
        };
        let ifindex = number("ifindex")?;
        let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
        let mut driver = [0u32; 49];
        driver[0] = 3; // ETHTOOL_GDRVINFO
        query(&fd, name, &mut driver)?;
        let veth = driver[1].to_ne_bytes() == *b"veth" && driver[2].to_ne_bytes()[0] == 0;
        let physical = path.join("device").try_exists()? && number("iflink")? == ifindex;
        if number("type")? != 1 || !(physical || veth) {
            return Err(unsupported(
                "only standalone physical Ethernet or proven veth topology is admitted",
            ));
        }
        let upper_ifindices = upper_ifindices(&path, ifindex)?;
        let mtu = number("mtu")?;
        if !(68..=65535).contains(&mtu) {
            return Err(unsupported("unsupported device MTU"));
        }
        let queues = bidirectional_queues(&path.join("queues"))?;
        let address = fs::read_to_string(path.join("address"))?;
        let mut mac = [0; 6];
        let octets: Vec<_> = address.trim().split(':').collect();
        if octets.len() != 6 {
            return Err(unsupported("invalid Ethernet address"));
        }
        for (out, text) in mac.iter_mut().zip(octets) {
            *out = u8::from_str_radix(text, 16)
                .map_err(|_| unsupported("invalid Ethernet address"))?;
        }
        let (xdp_features, zerocopy_max_segments, rx_metadata) = xdp_capabilities(ifindex)?;
        let vlan_metadata = rx_metadata & 4 != 0;
        if veth && !vlan_metadata {
            return Err(unsupported("veth requires authoritative RX VLAN metadata"));
        }
        if !vlan_metadata {
            reject_vlan_stripping(name)?;
        }
        if xdp_features & 3 != 3 {
            return Err(unsupported("native XDP basic/redirect support unavailable"));
        }
        let required = (mtu as usize + 22).div_ceil(FRAME_SIZE - 256 - METADATA_SIZE);
        if required > 1 && xdp_features & 32 == 0 {
            return Err(unsupported(
                "MTU requires advertised native XDP RX scatter/gather",
            ));
        }
        Ok(Self {
            name: name.into(),
            ifindex,
            upper_ifindices,
            queues,
            mtu,
            mac,
            xdp_features,
            zerocopy_max_segments,
            vlan_metadata,
        })
    }

    /// Check commitments without allocating UMEM; return the required RX chain length.
    pub fn validate_port_config(&self, mode: BindMode, config: PortConfig) -> io::Result<usize> {
        config.validate()?;
        let required = (self.mtu as usize + 22).div_ceil(FRAME_SIZE - 256 - METADATA_SIZE);
        if required > MAX_SEGMENTS
            || config.rx_frames < required
            || config.control_frames < required
            || config.bulk_frames < required
        {
            return Err(unsupported(
                "whole-packet frame commitments cannot cover device MTU",
            ));
        }
        if mode == BindMode::ZeroCopy
            && (self.xdp_features & 8 == 0
                || (required > 1 && self.zerocopy_max_segments < required as u32))
        {
            return Err(unsupported("zero-copy segment capability unavailable"));
        }
        Ok(required)
    }

    /// Recheck immutable admission facts, including the wire-only stripping-off proof.
    pub fn validate_current(&self) -> io::Result<()> {
        let fresh = Self::discover(&self.name)?;
        if fresh.ifindex != self.ifindex
            || fresh.upper_ifindices != self.upper_ifindices
            || fresh.queues != self.queues
            || fresh.mtu != self.mtu
            || fresh.mac != self.mac
            || fresh.xdp_features & !NDO_XMIT_FEATURES != self.xdp_features & !NDO_XMIT_FEATURES
            || fresh.zerocopy_max_segments != self.zerocopy_max_segments
            || fresh.vlan_metadata != self.vlan_metadata
        {
            return Err(unsupported("device facts changed before capture admission"));
        }
        Ok(())
    }

    pub fn open_ports<L>(
        &self,
        mode: BindMode,
        config: PortConfig,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Vec<Port<L>>> {
        self.validate_current()?;
        let required = self.validate_port_config(mode, config)?;
        self.queues
            .iter()
            .map(|&queue| {
                Port::open_device(
                    self.ifindex,
                    queue,
                    mode,
                    config,
                    self.mtu,
                    required > 1,
                    budget,
                )
            })
            .collect()
    }
}

fn bidirectional_queues(path: &Path) -> io::Result<Vec<u32>> {
    let mut queues = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if let Some(queue) = entry.file_name().to_string_lossy().strip_prefix("rx-") {
            let queue = queue
                .parse::<u32>()
                .map_err(|_| unsupported("invalid RX queue identity"))?;
            if queue >= 256 || queues.len() == 256 {
                return Err(unsupported("RX queue count must be 1..=256"));
            }
            require_queue_pair(path, queue)?;
            queues.push(queue);
        }
    }
    queues.sort_unstable();
    if queues.is_empty() || queues.iter().copied().ne(0..queues.len() as u32) {
        return Err(unsupported("RX queues must be nonempty and contiguous"));
    }
    Ok(queues)
}

fn require_queue_pair(path: &Path, queue: u32) -> io::Result<()> {
    for direction in ["rx", "tx"] {
        if !path.join(format!("{direction}-{queue}")).try_exists()? {
            return Err(unsupported("AF_XDP queue requires both RX and TX"));
        }
    }
    Ok(())
}

pub(crate) fn validate_queue(ifindex: u32, queue: u32) -> io::Result<()> {
    let mut name = [0; libc::IFNAMSIZ];
    // SAFETY: name has IFNAMSIZ bytes, as required by if_indextoname.
    if unsafe { libc::if_indextoname(ifindex, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful if_indextoname returned a NUL-terminated name in this buffer.
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
    let path = Path::new("/sys/class/net").join(std::ffi::OsStr::from_bytes(name.to_bytes()));
    let actual = fs::read_to_string(path.join("ifindex"))?;
    if actual.trim().parse::<u32>().ok() != Some(ifindex) {
        return Err(unsupported("AF_XDP interface identity changed before bind"));
    }
    require_queue_pair(&path.join("queues"), queue)
}

fn upper_ifindices(path: &Path, root: u32) -> io::Result<Vec<u32>> {
    let mut uppers = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "master" || name == "bridge" || name == "bonding" || name.starts_with("lower_") {
            return Err(unsupported(
                "stacked, bridged, bonded or enslaved XDP root topology",
            ));
        }
        if name.starts_with("upper_") {
            if uppers.len() == MAX_UPPER_INTERFACES {
                return Err(unsupported(
                    "direct upper interfaces exceed bounded capacity",
                ));
            }
            let index = fs::read_to_string(entry.path().join("ifindex"))?
                .trim()
                .parse::<u32>()
                .map_err(|_| unsupported("invalid upper interface identity"))?;
            if index == 0 || index == root {
                return Err(unsupported("invalid upper interface identity"));
            }
            uppers.push(index);
        }
    }
    uppers.sort_unstable();
    if uppers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(unsupported("duplicate upper interface identity"));
    }
    Ok(uppers)
}

fn socket(domain: i32, kind: i32, protocol: i32) -> io::Result<OwnedFd> {
    // SAFETY: no pointer arguments; returned descriptor is wrapped exactly once.
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn interface_name(name: &str) -> io::Result<[libc::c_char; libc::IFNAMSIZ]> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || name.contains('/')
        || name.as_bytes().contains(&0)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = [0; libc::IFNAMSIZ];
    for (out, byte) in bytes.iter_mut().zip(name.bytes()) {
        *out = byte as libc::c_char;
    }
    Ok(bytes)
}

fn query(fd: &OwnedFd, name: &str, words: &mut [u32]) -> io::Result<()> {
    query_named(fd, &interface_name(name)?, words)
}

fn query_named(
    fd: &OwnedFd,
    name: &[libc::c_char; libc::IFNAMSIZ],
    words: &mut [u32],
) -> io::Result<()> {
    // SAFETY: the fixed name is terminated and the ioctl buffer remains live.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name = *name;
    request.ifr_ifru.ifru_data = words.as_mut_ptr().cast();
    if unsafe { libc::ioctl(fd.as_raw_fd(), 0x8946, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const MAX_FEATURES: usize = 4096;
const NAMED_FEATURES: [&[u8]; 10] = [
    b"rx-vlan-hw-parse",
    b"rx-vlan-stag-hw-parse",
    b"rx-gro",
    b"rx-lro",
    b"tx-generic-segmentation",
    b"tx-tcp-segmentation",
    b"tx-tcp6-segmentation",
    b"rx-checksum",
    b"tx-checksum-ip-generic",
    b"rx-gro-hw",
];
const CONTEXT_HEADER: usize = 8 + 160 + 2 + 4 + NAMED_FEATURES.len() * 4;

/// Cold-funded ethtool state. Runtime checks never rediscover a device or allocate.
pub struct FeatureQuery {
    fd: OwnedFd,
    name: [libc::c_char; libc::IFNAMSIZ],
    count: usize,
    words: Vec<u32>,
    baseline: Vec<u32>,
    context: Vec<u8>,
    _reservation: MemoryReservation,
}

impl FeatureQuery {
    pub fn new(info: &DeviceInfo, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let name = interface_name(&info.name)?;
        let bookkeeping = budget
            .reserve(size_of::<Self>())
            .ok_or_else(|| io::Error::other("feature query memory budget exhausted"))?;
        let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
        let count = feature_count(&fd, &name)?;
        let blocks = count.div_ceil(32);
        let context_len = CONTEXT_HEADER + count * 32 + blocks * 4;
        // Fund both retained storage and cold dictionary scratch before allocating either.
        let scratch = budget
            .reserve((3 + count * 8) * 4)
            .ok_or_else(|| io::Error::other("feature dictionary memory budget exhausted"))?;
        let reservation = budget
            .reserve(size_of::<Self>() + (2 + blocks * 5) * 4 + context_len)
            .ok_or_else(|| io::Error::other("feature query memory budget exhausted"))?;
        drop(bookkeeping);
        let mut driver = [0u32; 49];
        driver[0] = 3;
        query_named(&fd, &name, &mut driver)?;
        let mut names = vec![0; 3 + count * 8];
        read_feature_names(&fd, &name, count, &mut names)?;
        let mut result = Self {
            fd,
            name,
            count,
            words: vec![0; 2 + blocks * 4],
            baseline: vec![0; blocks],
            context: vec![0; context_len],
            _reservation: reservation,
        };
        encode_feature_context(&driver, count, &names, &mut result.context)?;
        read_features(&result.fd, &result.name, count, &mut result.words)?;
        for (block, active) in result.baseline.iter_mut().enumerate() {
            *active = result.words[4 + block * 4];
        }
        result.observe()?;
        drop(names);
        drop(scratch);
        Ok(result)
    }

    /// Version 1: magic, five driver strings, firmware/bus applicability tags,
    /// LE feature count, named indices (u32::MAX = not advertised), dictionary,
    /// and latest observed LE active words. No ephemeral ifindex is encoded.
    pub fn context(&self) -> &[u8] {
        &self.context
    }

    /// True only when the valid current active bits equal the cold admission baseline.
    /// False retains the newly observed bits without rebinding that baseline. Errors
    /// preserve the last valid context and must disable optional polling at the caller.
    pub fn check(&mut self) -> io::Result<bool> {
        read_features(&self.fd, &self.name, self.count, &mut self.words)?;
        self.observe()
    }

    fn observe(&mut self) -> io::Result<bool> {
        validate_features(self.count, &self.words)?;
        let offset = CONTEXT_HEADER + self.count * 32;
        let mut unchanged = true;
        for (block, &baseline) in self.baseline.iter().enumerate() {
            let active = self.words[4 + block * 4];
            unchanged &= active == baseline;
            self.context[offset + block * 4..offset + (block + 1) * 4]
                .copy_from_slice(&active.to_le_bytes());
        }
        Ok(unchanged)
    }
}

fn feature_count(fd: &OwnedFd, name: &[libc::c_char; libc::IFNAMSIZ]) -> io::Result<usize> {
    let mask = (1u64 << 4).to_ne_bytes();
    let low = u32::from_ne_bytes(mask[..4].try_into().unwrap());
    let high = u32::from_ne_bytes(mask[4..].try_into().unwrap());
    let mut info = [0x37, 0, low, high, 0, 0];
    query_named(fd, name, &mut info)?;
    if info[0] != 0x37
        || info[2] != low
        || info[3] != high
        || !(1..=MAX_FEATURES).contains(&(info[4] as usize))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(info[4] as usize)
}

fn read_feature_names(
    fd: &OwnedFd,
    name: &[libc::c_char; libc::IFNAMSIZ],
    count: usize,
    names: &mut [u32],
) -> io::Result<()> {
    if !(1..=MAX_FEATURES).contains(&count) || names.len() != 3 + count * 8 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    names.fill(0);
    names[..3].copy_from_slice(&[0x1b, 4, count as u32]);
    query_named(fd, name, names)?;
    if names[..3] != [0x1b, 4, count as u32] {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn read_features(
    fd: &OwnedFd,
    name: &[libc::c_char; libc::IFNAMSIZ],
    count: usize,
    words: &mut [u32],
) -> io::Result<()> {
    if !(1..=MAX_FEATURES).contains(&count) || words.len() != 2 + count.div_ceil(32) * 4 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    words.fill(0);
    words[0] = 0x3a;
    words[1] = count.div_ceil(32) as u32;
    query_named(fd, name, words)?;
    validate_features(count, words)
}

fn validate_features(count: usize, words: &[u32]) -> io::Result<()> {
    if !(1..=MAX_FEATURES).contains(&count)
        || words.len() != 2 + count.div_ceil(32) * 4
        || words[0] != 0x3a
        || words[1] as usize != count.div_ceil(32)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if !count.is_multiple_of(32) {
        let outside = !((1u32 << (count % 32)) - 1);
        if words[words.len() - 4..]
            .iter()
            .any(|word| word & outside != 0)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(())
}

fn string_bytes(words: &[u32]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    if let Some(end) = bytes.iter().position(|&byte| byte == 0) {
        bytes[end..].fill(0);
    }
    bytes
}

fn encode_feature_context(
    driver: &[u32; 49],
    count: usize,
    names: &[u32],
    out: &mut [u8],
) -> io::Result<()> {
    if driver[0] != 3
        || !(1..=MAX_FEATURES).contains(&count)
        || names.len() != 3 + count * 8
        || names[..3] != [0x1b, 4, count as u32]
        || out.len() != CONTEXT_HEADER + count * 32 + count.div_ceil(32) * 4
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    out[..8].copy_from_slice(b"HXFEAT\0\x01");
    for index in 0..5 {
        out[8 + index * 32..8 + (index + 1) * 32]
            .copy_from_slice(&string_bytes(&driver[1 + index * 8..1 + (index + 1) * 8]));
    }
    let veth = &out[8..13] == b"veth\0";
    if out[8] == 0 || out[40] == 0 {
        return Err(io::ErrorKind::Unsupported.into());
    }
    // 1 = applicable/present, 2 = verified NotApplicable; unavailable is an error.
    for (tag, field) in [(168, 72), (169, 104)] {
        out[tag] = if veth {
            2
        } else if out[field] != 0 {
            1
        } else {
            return Err(io::ErrorKind::Unsupported.into());
        };
    }
    out[170..174].copy_from_slice(&(count as u32).to_le_bytes());
    out[174..CONTEXT_HEADER].fill(0xff);
    for index in 0..count {
        let bytes = string_bytes(&names[3 + index * 8..3 + (index + 1) * 8]);
        let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(32);
        out[CONTEXT_HEADER + index * 32..CONTEXT_HEADER + (index + 1) * 32].copy_from_slice(&bytes);
        for (named, wanted) in NAMED_FEATURES.iter().enumerate() {
            if &bytes[..end] == *wanted {
                let slot = &mut out[174 + named * 4..178 + named * 4];
                if slot != [0xff; 4] {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                slot.copy_from_slice(&(index as u32).to_le_bytes());
            }
        }
    }
    Ok(())
}

fn reject_vlan_stripping(name: &str) -> io::Result<()> {
    let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let name = interface_name(name)?;
    let count = feature_count(&fd, &name)?;
    let mut names = vec![0; 3 + count * 8];
    read_feature_names(&fd, &name, count, &mut names)?;
    let mut features = vec![0; 2 + count.div_ceil(32) * 4];
    read_features(&fd, &name, count, &mut features)?;
    let mut found_vlan = 0;
    for index in 0..count {
        let bytes = string_bytes(&names[3 + index * 8..3 + (index + 1) * 8]);
        let feature = &bytes[..bytes.iter().position(|&byte| byte == 0).unwrap_or(32)];
        if feature == NAMED_FEATURES[0] || feature == NAMED_FEATURES[1] {
            found_vlan |= if feature == NAMED_FEATURES[0] { 1 } else { 2 };
            if features[4 + index / 32 * 4] & (1 << (index % 32)) != 0 {
                return Err(unsupported(
                    "active RX VLAN stripping has no admitted metadata recovery",
                ));
            }
        }
    }
    if found_vlan != 3 {
        return Err(unsupported("RX VLAN stripping facts unavailable"));
    }
    Ok(())
}

fn attributes(mut bytes: &[u8], mut f: impl FnMut(u16, &[u8]) -> io::Result<()>) -> io::Result<()> {
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(unsupported("truncated netlink attribute"));
        }
        let length = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff;
        if length < 4 || length > bytes.len() {
            return Err(unsupported("invalid netlink attribute extent"));
        }
        f(kind, &bytes[4..length])?;
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            return Err(unsupported("truncated netlink attribute padding"));
        }
        bytes = &bytes[aligned..];
    }
    Ok(())
}

fn xdp_capabilities(ifindex: u32) -> io::Result<(u64, u32, u64)> {
    let fd = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_GENERIC)?;
    // SAFETY: initialized sockaddr_nl identifies the kernel, not another userspace peer.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            size_of::<libc::sockaddr_nl>() as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: timeval is the exact socket option payload.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&timeout).cast(),
            size_of::<libc::timeval>() as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    fn request(
        fd: &OwnedFd,
        family: u16,
        command: u8,
        kind: u16,
        value: &[u8],
        sequence: u32,
    ) -> io::Result<Vec<u8>> {
        let attr_len = value.len() + 4;
        let mut bytes = vec![0u8; 20 + ((attr_len + 3) & !3)];
        let length = bytes.len() as u32;
        bytes[0..4].copy_from_slice(&length.to_ne_bytes());
        bytes[4..6].copy_from_slice(&family.to_ne_bytes());
        bytes[6..8].copy_from_slice(&1u16.to_ne_bytes());
        bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
        bytes[16] = command;
        bytes[17] = 1;
        bytes[20..22].copy_from_slice(&(attr_len as u16).to_ne_bytes());
        bytes[22..24].copy_from_slice(&kind.to_ne_bytes());
        bytes[24..24 + value.len()].copy_from_slice(value);
        // SAFETY: both syscall buffers have their stated extents and remain live.
        if unsafe { libc::send(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) }
            != bytes.len() as isize
        {
            return Err(io::Error::last_os_error());
        }
        let mut response = vec![0u8; 65536];
        let received = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                response.as_mut_ptr().cast(),
                response.len(),
                libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received < 20 || received as usize > response.len() {
            return Err(unsupported("invalid netdev reply size"));
        }
        response.truncate(received as usize);
        let size = u32::from_ne_bytes(response[0..4].try_into().unwrap()) as usize;
        let reply = u16::from_ne_bytes(response[4..6].try_into().unwrap());
        if u32::from_ne_bytes(response[8..12].try_into().unwrap()) != sequence
            || size != response.len()
        {
            return Err(unsupported("unexpected netdev reply identity"));
        }
        if reply == 2 {
            let code = i32::from_ne_bytes(response[16..20].try_into().unwrap());
            return Err(if code < 0 {
                io::Error::from_raw_os_error(-code)
            } else {
                unsupported("netdev returned no facts")
            });
        }
        if reply != family {
            return Err(unsupported("unexpected netdev reply family"));
        }
        Ok(response)
    }
    let family_name = CString::new("netdev").unwrap();
    let response = request(&fd, 0x10, 3, 2, family_name.as_bytes_with_nul(), 1)?;
    let mut family = None;
    attributes(&response[20..], |kind, value| {
        if kind == 1 && value.len() == 2 {
            family = Some(u16::from_ne_bytes(value.try_into().unwrap()));
        }
        Ok(())
    })?;
    let response = request(
        &fd,
        family.ok_or_else(|| unsupported("netdev generic family unavailable"))?,
        1,
        1,
        &ifindex.to_ne_bytes(),
        2,
    )?;
    let mut index = None;
    let mut features = None;
    let mut maximum = 0;
    let mut rx_metadata = 0;
    attributes(&response[20..], |kind, value| {
        match (kind, value.len()) {
            (1, 4) => index = Some(u32::from_ne_bytes(value.try_into().unwrap())),
            (3, 8) => features = Some(u64::from_ne_bytes(value.try_into().unwrap())),
            (4, 4) => maximum = u32::from_ne_bytes(value.try_into().unwrap()),
            (5, 8) => rx_metadata = u64::from_ne_bytes(value.try_into().unwrap()),
            _ => {}
        }
        Ok(())
    })?;
    if index != Some(ifindex) {
        return Err(unsupported("netdev interface identity mismatch"));
    }
    Ok((
        features.ok_or_else(|| unsupported("XDP feature advertisement unavailable"))?,
        maximum,
        rx_metadata,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn driver_fixture(veth: bool) -> [u32; 49] {
        let mut driver = [0; 49];
        driver[0] = 3;
        for (field, text) in [
            (
                0,
                if veth {
                    b"veth".as_slice()
                } else {
                    b"ixgbe".as_slice()
                },
            ),
            (1, b"6.12".as_slice()),
            (
                2,
                if veth {
                    b"".as_slice()
                } else {
                    b"firmware-1".as_slice()
                },
            ),
            (
                3,
                if veth {
                    b"".as_slice()
                } else {
                    b"0000:01:00.0".as_slice()
                },
            ),
        ] {
            let mut bytes = [0; 32];
            bytes[..text.len()].copy_from_slice(text);
            for (word, chunk) in driver[1 + field * 8..1 + (field + 1) * 8]
                .iter_mut()
                .zip(bytes.as_chunks::<4>().0)
            {
                *word = u32::from_ne_bytes(*chunk);
            }
        }
        driver
    }

    fn dictionary_fixture(count: usize) -> Vec<u32> {
        let mut names = vec![0; 3 + count * 8];
        names[..3].copy_from_slice(&[0x1b, 4, count as u32]);
        for (index, name) in NAMED_FEATURES.iter().take(count).enumerate() {
            let mut bytes = [0; 32];
            bytes[..name.len()].copy_from_slice(name);
            for (word, chunk) in names[3 + index * 8..3 + (index + 1) * 8]
                .iter_mut()
                .zip(bytes.as_chunks::<4>().0)
            {
                *word = u32::from_ne_bytes(*chunk);
            }
        }
        names
    }

    #[test]
    fn feature_context_distinguishes_not_advertised_inapplicable_and_unavailable() {
        let names = dictionary_fixture(2);
        let mut out = vec![0; CONTEXT_HEADER + 64 + 4];
        encode_feature_context(&driver_fixture(true), 2, &names, &mut out).unwrap();
        assert_eq!(&out[..8], b"HXFEAT\0\x01");
        assert_eq!(&out[168..170], &[2, 2]);
        assert_eq!(&out[174..178], &0u32.to_le_bytes());
        assert_eq!(&out[178..182], &1u32.to_le_bytes());
        assert_eq!(&out[182..186], &u32::MAX.to_le_bytes());
        let veth = out.clone();
        let mut physical = driver_fixture(false);
        encode_feature_context(&physical, 2, &names, &mut out).unwrap();
        assert_eq!(&out[168..170], &[1, 1]);
        assert_ne!(out, veth);
        physical[17..25].fill(0);
        assert_eq!(
            encode_feature_context(&physical, 2, &names, &mut out)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        physical = driver_fixture(false);
        physical[25..33].fill(0);
        assert!(encode_feature_context(&physical, 2, &names, &mut out).is_err());
        let mut duplicate = names.clone();
        duplicate[11..19].copy_from_slice(&names[3..11]);
        assert!(encode_feature_context(&driver_fixture(true), 2, &duplicate, &mut out).is_err());
    }

    #[test]
    fn fixed_feature_shape_and_observed_changes_preserve_admission_baseline() {
        for count in [1usize, 32, 33, MAX_FEATURES] {
            let blocks = count.div_ceil(32);
            let mut words = vec![0; 2 + blocks * 4];
            words[..2].copy_from_slice(&[0x3a, blocks as u32]);
            validate_features(count, &words).unwrap();
            words[1] += 1;
            assert!(validate_features(count, &words).is_err());
            words[1] -= 1;
            assert!(validate_features(count, &words[..words.len() - 1]).is_err());
            if count % 32 != 0 {
                words[4 + (blocks - 1) * 4] = 1 << (count % 32);
                assert!(validate_features(count, &words).is_err());
            }
        }
        assert!(validate_features(0, &[]).is_err());
        assert!(validate_features(MAX_FEATURES + 1, &[]).is_err());
        let budget = MemoryBudget::new(1 << 20);
        let mut query = FeatureQuery {
            fd: fs::File::open("/dev/null").unwrap().into(),
            name: interface_name("fixture0").unwrap(),
            count: 2,
            words: vec![0x3a, 1, 3, 0, 1, 0],
            baseline: vec![1],
            context: vec![0; CONTEXT_HEADER + 64 + 4],
            _reservation: budget.reserve(4096).unwrap(),
        };
        encode_feature_context(
            &driver_fixture(true),
            2,
            &dictionary_fixture(2),
            &mut query.context,
        )
        .unwrap();
        assert!(query.observe().unwrap());
        let admitted = query.context().to_vec();
        query.words[4] = 2;
        assert!(!query.observe().unwrap());
        assert!(!query.observe().unwrap());
        assert_eq!(query.baseline, [1]);
        assert_eq!(&query.context()[CONTEXT_HEADER + 64..], &2u32.to_le_bytes());
        assert_ne!(query.context(), admitted);
        let changed = query.context().to_vec();
        query.words[1] = 2;
        assert!(query.observe().is_err());
        assert_eq!(query.context(), changed);
        assert!(query.check().is_err());
        assert_eq!(query.context(), changed);
        query.words.copy_from_slice(&[0x3a, 1, 3, 0, 1, 0]);
        assert!(query.observe().unwrap());
        assert_eq!(query.context(), admitted);
        drop(query);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn binding_preflight_requires_real_zero_copy_and_complete_chains() {
        let mut device = DeviceInfo {
            name: "test0".into(),
            ifindex: 2,
            upper_ifindices: vec![],
            queues: vec![0, 1],
            mtu: 1500,
            mac: [2, 0, 0, 0, 0, 1],
            xdp_features: 3 | 32,
            zerocopy_max_segments: 0,
            vlan_metadata: false,
        };
        let config = PortConfig {
            rx_frames: 4,
            control_frames: 4,
            bulk_frames: 4,
            ring_size: 8,
        };
        assert_eq!(
            device.validate_port_config(BindMode::Copy, config).unwrap(),
            1
        );
        assert_eq!(
            device
                .validate_port_config(BindMode::ZeroCopy, config)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        device.xdp_features |= 8;
        assert_eq!(
            device
                .validate_port_config(BindMode::ZeroCopy, config)
                .unwrap(),
            1
        );
        device.mtu = 9000;
        assert_eq!(
            device.validate_port_config(BindMode::Copy, config).unwrap(),
            3
        );
        device.zerocopy_max_segments = 2;
        assert!(
            device
                .validate_port_config(BindMode::ZeroCopy, config)
                .is_err()
        );
        device.zerocopy_max_segments = 3;
        assert_eq!(
            device
                .validate_port_config(BindMode::ZeroCopy, config)
                .unwrap(),
            3
        );
        for insufficient in [
            PortConfig {
                rx_frames: 2,
                ..config
            },
            PortConfig {
                control_frames: 2,
                ..config
            },
            PortConfig {
                bulk_frames: 2,
                ..config
            },
            PortConfig {
                ring_size: 7,
                ..config
            },
        ] {
            assert!(
                device
                    .validate_port_config(BindMode::Copy, insufficient)
                    .is_err()
            );
            assert!(
                device
                    .validate_port_config(BindMode::ZeroCopy, insufficient)
                    .is_err()
            );
        }
    }

    struct SysfsFixture(std::path::PathBuf);

    impl SysfsFixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("honk-xsk-device-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn upper(&self, name: &str, index: &str) {
            let path = self.0.join(name);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("ifindex"), index).unwrap();
        }
    }

    impl Drop for SysfsFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn every_discovered_rx_queue_requires_a_transmit_peer() {
        let fixture = SysfsFixture::new();
        for queue in ["rx-0", "tx-0", "rx-1"] {
            fs::create_dir(fixture.0.join(queue)).unwrap();
        }
        assert_eq!(
            bidirectional_queues(&fixture.0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        fs::create_dir(fixture.0.join("tx-1")).unwrap();
        assert_eq!(bidirectional_queues(&fixture.0).unwrap(), [0, 1]);
        fs::remove_dir(fixture.0.join("rx-1")).unwrap();
        assert_eq!(bidirectional_queues(&fixture.0).unwrap(), [0]);
        assert!(require_queue_pair(&fixture.0, 1).is_err());
        fs::remove_dir(fixture.0.join("rx-0")).unwrap();
        assert!(bidirectional_queues(&fixture.0).is_err());
        fs::create_dir(fixture.0.join("rx-1")).unwrap();
        assert!(bidirectional_queues(&fixture.0).is_err());
    }

    #[test]
    fn direct_uppers_are_sorted_facts_without_relaxing_root_guards() {
        let fixture = SysfsFixture::new();
        fixture.upper("upper_a", "20\n");
        fixture.upper("upper_b", "4\n");
        fixture.upper("upper_b/upper_nested", "99\n");
        assert_eq!(upper_ifindices(&fixture.0, 2).unwrap(), [4, 20]);
        for guard in ["master", "bridge", "bonding", "lower_eth0"] {
            fs::write(fixture.0.join(guard), "").unwrap();
            assert!(upper_ifindices(&fixture.0, 2).is_err());
            fs::remove_file(fixture.0.join(guard)).unwrap();
        }
        for invalid in ["0", "2", "20", "not-an-ifindex"] {
            fs::write(fixture.0.join("upper_b/ifindex"), invalid).unwrap();
            assert!(upper_ifindices(&fixture.0, 2).is_err());
        }
        fs::remove_file(fixture.0.join("upper_b/ifindex")).unwrap();
        assert!(upper_ifindices(&fixture.0, 2).is_err());
    }

    #[test]
    fn upper_discovery_is_bounded_before_growing_past_capacity() {
        let fixture = SysfsFixture::new();
        fixture.upper("target", "4");
        for index in 0..=MAX_UPPER_INTERFACES {
            std::os::unix::fs::symlink("target", fixture.0.join(format!("upper_{index}"))).unwrap();
        }
        assert_eq!(
            upper_ifindices(&fixture.0, 2).unwrap_err().to_string(),
            "direct upper interfaces exceed bounded capacity"
        );
    }

    #[test]
    fn attribute_extents_fail_closed() {
        assert!(attributes(&[3, 0, 1, 0], |_, _| Ok(())).is_err());
        assert!(attributes(&[8, 0, 1, 0, 0], |_, _| Ok(())).is_err());
        let mut seen = false;
        attributes(&[8, 0, 1, 0, 7, 0, 0, 0], |kind, bytes| {
            assert_eq!(kind, 1);
            assert_eq!(bytes, &[7, 0, 0, 0]);
            seen = true;
            Ok(())
        })
        .unwrap();
        assert!(seen);
    }
}
